#!/usr/bin/env node
// vetcode: finds malware, supply-chain risks, leaked secrets and vulnerability candidates
// in a project. Read-only: it never installs, builds or runs anything from the target.
//
//   node vet.mjs [path] [options]
//     --json <file>     also write the full results as JSON
//     --sarif <file>    also write SARIF 2.1.0 (GitHub code scanning)
//     --online          look up dependencies on OSV.dev (known vulnerabilities and malware)
//                       and run semgrep / osv-scanner / trivy if they are installed
//     --deps            read installed node_modules: install scripts and malware patterns
//     --history         search git history for secrets that were committed and removed
//     --diff [base]     only files changed against base (default: uncommitted changes)
//     --no-ignore       ignore .vetcodeignore and inline vetcode-ignore comments
//     --baseline <file> hide findings already in an earlier --json report (report only new ones)
//     --mcp-lock <file> remember MCP servers and tool descriptions; report changes (rug pulls)
//     --no-tools        do not run external tools even if installed
//     --fail-on <sev>   exit 1 if a finding at this severity or worse exists (for CI)
//     --quiet           no progress messages
//
//   node vet.mjs --cargo-diff <old> [new] [path]
//     What a Cargo.lock update brings in. <old> and <new> are Cargo.lock files or git refs
//     (HEAD, main, HEAD~1); without <new>, the Cargo.lock in path. Every crate the update adds
//     or changes is downloaded from crates.io and read, never built; the report names new build
//     scripts, new build-dependencies and build-time abilities the new version did not have.
//     Exit 1 when a crate gets a verdict. Takes --json and --quiet.
//
//   node vet.mjs --action-diff <owner/repo@old> <owner/repo@new>
//   node vet.mjs --action-diff <old-ref> [new-ref] [path]
//     What a GitHub Action bump adds: the two versions of one action, or every `uses:` whose ref
//     changed in .github/workflows (and composite actions) between two git refs (without new-ref,
//     the working tree). Both versions are downloaded from GitHub and read, never run. Exit 1 when
//     a bump adds something serious (a download that is run, runner memory, a new secret name, a
//     new pre or post step). Takes --json.
import fs from "node:fs";
import { vet, VERSION } from "./lib/index.mjs";
import { markdown } from "./lib/report.mjs";
import { sarif } from "./lib/sarif.mjs";
import { rank, SEVERITIES } from "./lib/engine.mjs";

const args = process.argv.slice(2);
const flag = name => { const i = args.indexOf(name); if (i < 0) return false; args.splice(i, 1); return true; };
const value = (name, optional = false) => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) { if (!optional) { console.error(`${name} needs a value`); process.exit(2); } args.splice(i, 1); return ""; }
  args.splice(i, 2);
  return v;
};

if (flag("--help") || flag("-h")) { console.log(fs.readFileSync(new URL(import.meta.url), "utf8").split("\n").filter(l => l.startsWith("//")).map(l => l.slice(3)).join("\n")); process.exit(0); }
if (flag("--version")) { console.log(VERSION); process.exit(0); }

if (args.includes("--action-diff")) {
  const { spawnSync } = await import("node:child_process");
  const path = await import("node:path");
  const { diffAction, bumpsBetween, actionDiffMarkdown } = await import("./lib/actions.mjs");
  const json = value("--json");
  const rest = args.slice(args.indexOf("--action-diff") + 1).filter(a => !a.startsWith("--"));
  const spec = s => /^([\w.-]+)\/([\w.-]+)((?:\/[^@]+)?)@(.+)$/.exec(s || "");
  let results = [];
  if (spec(rest[0])) {
    const [a, b] = [spec(rest[0]), spec(rest[1])];
    if (!b) { console.error("--action-diff owner/repo@old owner/repo@new"); process.exit(2); }
    results.push(await diffAction(a[1], a[2], a[4], b[4], { subpath: a[3].replace(/^\//, "") }));
  } else {
    const dir = rest.length === 3 ? rest[2] : rest[1] && fs.existsSync(rest[1]) && fs.statSync(rest[1]).isDirectory() ? rest[1] : ".";
    const [oldRef, newRef] = [rest[0], rest[1] && rest[1] !== dir ? rest[1] : null];
    if (!oldRef) { console.error("--action-diff needs two actions or a git ref"); process.exit(2); }
    const git = (...a) => spawnSync("git", ["-C", dir, ...a], { encoding: "utf8", maxBuffer: 64 << 20 });
    const listAt = ref => (ref ? git("ls-tree", "-r", "--name-only", ref) : git("ls-files")).stdout.split("\n").filter(f => /^\.github\/workflows\/[^/]+\.ya?ml$|(?:^|\/)action\.ya?ml$/.test(f));
    const textAt = (ref, f) => ref ? git("show", `${ref}:${f}`).stdout || "" : (() => { try { return fs.readFileSync(path.join(dir, f), "utf8"); } catch { return ""; } })();
    const bumps = bumpsBetween(listAt(oldRef).map(f => textAt(oldRef, f)), listAt(newRef).map(f => textAt(newRef, f)));
    for (const b of bumps) results.push(await diffAction(b.to.owner, b.to.repo, b.from.ref, b.to.ref, { subpath: b.to.path }).then(r => ({ ...r, from: b.from.comment || b.from.ref, to: b.to.comment || b.to.ref })));
    if (!bumps.length) { console.log("No `uses:` line changed its ref."); process.exit(0); }
  }
  if (json) fs.writeFileSync(json, JSON.stringify(results, (k, v) => v instanceof Set ? [...v] : v, 2));
  console.log(actionDiffMarkdown(results));
  process.exit(results.some(r => r.diff?.serious.length) ? 1 : 0);
}

if (args.includes("--cargo-diff")) {
  const { spawnSync } = await import("node:child_process");
  const path = await import("node:path");
  const { cargoDiff, cargoDiffMarkdown } = await import("./lib/rust.mjs");
  const json = value("--json"), quiet = flag("--quiet");
  const i = args.indexOf("--cargo-diff"), rest = args.slice(i + 1).filter(a => !a.startsWith("--"));
  const dir = rest.length === 3 ? rest[2] : rest.length === 2 && fs.existsSync(rest[1]) && fs.statSync(rest[1]).isDirectory() ? rest[1] : ".";
  const [oldSpec, newSpec] = [rest[0], rest[1] && rest[1] !== dir ? rest[1] : null];
  if (!oldSpec) { console.error("--cargo-diff needs the old Cargo.lock or a git ref"); process.exit(2); }
  const lockOf = spec => {
    if (fs.existsSync(spec) && fs.statSync(spec).isFile()) return fs.readFileSync(spec, "utf8");
    const top = spawnSync("git", ["-C", dir, "rev-parse", "--show-toplevel"], { encoding: "utf8" }).stdout.trim();
    const rel = top ? path.relative(top, path.resolve(dir, "Cargo.lock")).split(path.sep).join("/") : "Cargo.lock";
    const r = spawnSync("git", ["-C", dir, "show", `${spec}:${rel}`], { encoding: "utf8", maxBuffer: 64 << 20 });
    if (r.status !== 0) { console.error(`Could not read ${spec}: not a file, and git has no ${rel} at that ref`); process.exit(2); }
    return r.stdout;
  };
  const before = lockOf(oldSpec), after = newSpec ? lockOf(newSpec) : fs.readFileSync(path.join(dir, "Cargo.lock"), "utf8");
  const d = await cargoDiff(before, after, { vet, log: quiet ? () => {} : m => console.error(`vetcode: ${m}`) });
  if (json) fs.writeFileSync(json, JSON.stringify(d, null, 2));
  process.stdout.write(cargoDiffMarkdown(d, `${oldSpec} → ${newSpec || "working Cargo.lock"}`));
  process.exit(d.level === "warning" ? 1 : 0);
}

const opts = {
  json: value("--json"), sarif: value("--sarif"), baseline: value("--baseline"), mcpLock: value("--mcp-lock"), failOn: value("--fail-on"), diff: value("--diff", true),
  online: flag("--online"), deps: flag("--deps"), history: flag("--history"),
  noIgnore: flag("--no-ignore"), tools: !flag("--no-tools"), quiet: flag("--quiet"),
};
if (opts.failOn && !SEVERITIES.includes(opts.failOn)) { console.error(`--fail-on must be one of ${SEVERITIES.join(", ")}`); process.exit(2); }
const target = args.find(a => !a.startsWith("--")) || ".";
if (!fs.existsSync(target)) { console.error(`No such path: ${target}`); process.exit(2); }

opts.log = opts.quiet ? () => {} : m => console.error(`vetcode: ${m}`);
const result = await vet(target, opts);
if (opts.json) fs.writeFileSync(opts.json, JSON.stringify(result, null, 2));
if (opts.sarif) fs.writeFileSync(opts.sarif, JSON.stringify(sarif(result), null, 2));
process.stdout.write(markdown(result));
if (opts.json && !opts.quiet) console.error(`vetcode: JSON written to ${opts.json}`);
if (opts.failOn && result.findings.some(f => rank(f.severity) <= rank(opts.failOn) && f.confidence !== "low")) process.exit(1);
