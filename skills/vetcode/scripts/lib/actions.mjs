// GitHub Actions version diffs. A workflow runs third-party actions with the repository's token and
// secrets, and Dependabot and Renovate bump them in pull requests that almost nobody reads. In the
// tj-actions/changed-files and reviewdog/action-setup attacks (March 2025) the malicious change sat
// in the bundled dist/index.js while the source looked unchanged. So the question here is: what can
// the new version do that the old one could not?
//
// Both versions are fetched as tarballs of their commits and read; nothing is installed or run.
// Almost every action already uses the network, starts programs and reads the environment, so the
// six abilities rarely change. The diff also goes one level finer: hosts it names, programs it
// starts, environment and secret names it reads, downloads that are then run, reads of the runner's
// process memory, and the action's own shape (runs.using, pre and post steps, token inputs).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { capabilitiesOf } from "./capabilities.mjs";
import { decoded } from "./normalize.mjs";

// ---- workflows: which actions a change bumps ----

const USES = /^\s*-?\s*uses:\s*["']?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)((?:\/[^@\s"']+)?)@([^\s"'#]+)["']?\s*(?:#\s*(\S+))?/gm;
/** Every third-party `uses: owner/repo[/path]@ref` in a workflow or composite action, with the version comment Dependabot keeps next to a SHA. */
export function usesOf(text) {
  return [...String(text).matchAll(USES)].map(m => ({ owner: m[1], repo: m[2], path: m[3].replace(/^\//, ""), ref: m[4], comment: m[5] || null, key: `${m[1]}/${m[2]}${m[3]}`.toLowerCase() }));
}

/** The actions whose ref differs between two sets of workflow files: [{ key, from, to }]. */
export function bumpsBetween(oldTexts, newTexts) {
  const refs = texts => { const m = new Map(); for (const t of texts) for (const u of usesOf(t)) { if (!m.has(u.key)) m.set(u.key, new Set()); m.get(u.key).add(JSON.stringify(u)); } return m; };
  const before = refs(oldTexts), after = refs(newTexts), out = [];
  for (const [key, set] of after) {
    const now = [...set].map(s => JSON.parse(s)), was = [...(before.get(key) || [])].map(s => JSON.parse(s));
    for (const n of now) if (was.length && !was.some(w => w.ref === n.ref)) out.push({ key, from: was[0], to: n });
  }
  return out;
}

// ---- reading one version ----

const read = f => { try { return fs.statSync(f).size < 40e6 ? fs.readFileSync(f, "utf8") : ""; } catch { return ""; } };
const yamlValue = (text, key) => new RegExp(`^\\s*${key}:\\s*["']?([^"'\\n#]+?)["']?\\s*(?:#.*)?$`, "m").exec(text)?.[1]?.trim() || null;

/** action.yml as far as this needs it: how it runs, what runs, its inputs and their defaults. */
export function actionManifest(dir) {
  const file = ["action.yml", "action.yaml"].map(n => path.join(dir, n)).find(f => fs.existsSync(f));
  const text = file ? read(file) : "";
  const runs = /^runs:\s*$([\s\S]*?)(?=^\S|(?![\s\S]))/m.exec(text)?.[1] || "";
  const inputs = {};
  const inputsBlock = /^inputs:\s*$([\s\S]*?)(?=^\S|(?![\s\S]))/m.exec(text)?.[1] || "";
  for (const m of inputsBlock.matchAll(/^ {2}([\w-]+):\s*$([\s\S]*?)(?=^ {2}[\w-]+:\s*$|(?![\s\S]))/gm)) inputs[m[1]] = { default: yamlValue(m[2], "default") };
  // Composite steps: the text of each run: block (block scalars included) and the actions it uses.
  const runBlocks = [];
  for (const m of runs.matchAll(/^(\s*)(?:-\s+)?run:\s*([|>][-+]?)?\s*(.*)$/gm)) {
    if (!m[2]) { runBlocks.push(m[3]); continue; }
    const start = m.index + m[0].length, rest = runs.slice(start).split("\n").slice(1), body = [];
    let indent = null;
    for (const l of rest) { if (!l.trim()) { body.push(""); continue; } const ind = l.match(/^\s*/)[0].length; if (indent === null) indent = ind; if (ind < indent) break; body.push(l.slice(indent)); }
    runBlocks.push(body.join("\n"));
  }
  return { file, using: yamlValue(runs, "using"), main: yamlValue(runs, "main"), pre: yamlValue(runs, "pre"), post: yamlValue(runs, "post"),
    image: yamlValue(runs, "image"), entrypoint: yamlValue(runs, "entrypoint"), inputs, runBlocks, uses: usesOf(runs) };
}

// What a shell script or a JavaScript bundle names, finer than the six abilities.
const HOST = /["'`](?:https?|wss?):\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?[/"'`?#]/gi;
const SHELL_HOST = /\b(?:https?|wss?):\/\/([a-z0-9.-]+\.[a-z]{2,})/gi;
const JS_PROGRAM = /\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|getExecOutput|which)\s*\(\s*["'`]([\w./-]+)/g;
const JS_ENV = /process\.env(?:\.([A-Z_][A-Z0-9_]*)|\[\s*["']([A-Z_][A-Z0-9_]*)["']\s*\])/g;
const SHELL_ENV = /\$\{?([A-Z_][A-Z0-9_]{2,})\}?/g;
const SECRETISH = /TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|CREDENTIAL|NPM_AUTH|PAT\b/;
const PROC_MEM = /\/proc\/(?:\$\{?\w+\}?|\d+|self|\*|[\w${}]+)\/(?:mem|maps|environ)\b|Runner\.Worker|memdump/;
// A download that is then run: piped into an interpreter, or saved, made executable and started.
// Decoding into a shell is the same thing without the download (reviewdog/action-setup's install.sh).
// Decoded text piped into any program, also one named by a variable ("| $SCRIPT_RUNNER", as in the real
// reviewdog commit), or handed to eval, is run all the same.
const DOWNLOAD_RUN = /base64\s+(?:-d|--decode|-D)\b[^\n;]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da)?sh\b|python3?\b|perl\b|node\b|"?\$\{?[A-Za-z_]\w*\}?)|\beval\s+"?\$\([^)\n]*base64\s+(?:-d|--decode)|(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b|(?:curl|wget)\b[^\n]*-[oO]\s*(\S+)[\s\S]{0,300}?chmod\s+\+?[0-7]*x[\s\S]{0,200}?\.\/|downloadTool\([\s\S]{0,400}?(?:chmod|exec(?:File)?)\(/;
const SHELL_BUILTINS = new Set("echo printf cd export set unset if then else elif fi for do done while case esac in function return exit local read test true false shift source eval exec trap wait sleep cat ls cp mv rm mkdir touch grep sed awk tr cut head tail sort uniq wc find xargs tee dirname basename pwd env date seq jq yq [ [[ ]] ]] { } ( ) shopt declare readonly let".split(" "));

function shellFacts(text, f) {
  for (const m of text.matchAll(SHELL_HOST)) f.hosts.add(m[1].toLowerCase());
  for (const m of text.matchAll(SHELL_ENV)) f.env.add(m[1]);
  for (const line of text.split("\n")) for (const seg of line.split(/\|\||&&|\||;/)) {
    const w = seg.trim().replace(/^(?:sudo|time|nohup|env\s+\S+=\S+)\s+/, "").split(/\s+/)[0];
    if (w && /^[\w./-]+$/.test(w) && !SHELL_BUILTINS.has(w) && !/^[A-Z_]+=/.test(w) && !/^\$/.test(w)) f.programs.add(path.basename(w));
  }
  // Each one by what it says, so a new one shows next to an old one (the official installer piped to sh).
  for (const m of text.matchAll(new RegExp(DOWNLOAD_RUN.source, "g"))) f.downloadRun.add(m[0].replace(/\s+/g, " ").slice(0, 120));
  for (const m of text.matchAll(new RegExp(PROC_MEM.source, "g"))) f.procMem.add(m[0]);
}
function jsFacts(text, f) {
  // Encoded payloads are read as what they decode to (tj-actions hid its script in base64).
  const b64 = [...text.matchAll(/(?:Buffer\.from|atob)\(\s*["'`]([A-Za-z0-9+/=]{40,})["'`]/g)].map(m => { try { return Buffer.from(m[1], "base64").toString("utf8"); } catch { return ""; } }).filter(t => /^[\x09\x0a\x0d\x20-\x7e]+$/.test(t));
  const view = [text, decoded(text) || "", ...b64].join("\n");
  // What a base64 string decodes to is usually a command line for a shell: read it as one.
  for (const t of b64) shellFacts(t, f);
  for (const m of view.matchAll(HOST)) f.hosts.add(m[1].toLowerCase());
  for (const m of view.matchAll(JS_PROGRAM)) f.programs.add(path.basename(m[1]));
  for (const m of view.matchAll(JS_ENV)) f.env.add(m[1] || m[2]);
  for (const c of capabilitiesOf(view)) f.abilities.add(c);
  // Shell text inside strings (exec("curl … | bash")) is read as shell too.
  for (const m of view.matchAll(/["'`]((?:[^"'`\\\n]|\\.){8,400}?(?:curl|wget|bash|sh -c|python3?|sudo)[^"'`\n]*)["'`]/g)) shellFacts(m[1], f);
  for (const m of view.matchAll(new RegExp(PROC_MEM.source, "g"))) f.procMem.add(m[0]);
}

/** What one version of an action can do, read from what runs (the entry points, composite steps, Dockerfile). */
export function actionProfile(dir) {
  const m = actionManifest(dir);
  const f = { using: m.using, pre: !!m.pre, post: !!m.post, inputs: m.inputs, uses: m.uses.map(u => `${u.owner}/${u.repo}${u.path ? "/" + u.path : ""}`),
    abilities: new Set(), hosts: new Set(), programs: new Set(), env: new Set(), downloadRun: new Set(), procMem: new Set(), files: [] };
  const js = [m.main, m.pre, m.post].filter(Boolean).map(p => path.join(dir, p));
  for (const file of js) { const t = read(file); if (t) { f.files.push(path.relative(dir, file)); jsFacts(t, f); } }
  for (const block of m.runBlocks) { shellFacts(block, f); for (const c of capabilitiesOf(block)) f.abilities.add(c); if (/\bcurl\b|\bwget\b/.test(block)) f.abilities.add("uses the network"); }
  // Scripts a composite step runs from the action's own folder.
  // The action's folder is written three ways: ${{ github.action_path }}, $GITHUB_ACTION_PATH, ${GITHUB_ACTION_PATH}.
  // (reviewdog/action-setup runs "$GITHUB_ACTION_PATH/install.sh"; the first look read only the first form and missed it.)
  for (const block of m.runBlocks) for (const s of block.matchAll(/(?:\$\{\{\s*github\.action_path\s*\}\}|\$\{?GITHUB_ACTION_PATH\}?)\/([\w./-]+\.(?:sh|bash|js|mjs|cjs|py|ps1))/g)) {
    const t = read(path.join(dir, s[1]));
    if (t) { f.files.push(s[1]); (/\.(c|m)?js$/.test(s[1]) ? jsFacts : shellFacts)(t, f); for (const c of capabilitiesOf(t)) f.abilities.add(c); }
  }
  if (m.using === "docker" && m.image && !/^docker:\/\//.test(m.image)) {
    const df = read(path.join(dir, m.image));
    if (df) { f.files.push(m.image); shellFacts(df.replace(/^\s*(?:RUN|ENTRYPOINT|CMD)\s+/gm, ""), f); }
    for (const e of [m.entrypoint, "entrypoint.sh"].filter(Boolean)) { const t = read(path.join(dir, e.replace(/^\//, ""))); if (t) { f.files.push(e); shellFacts(t, f); } }
  }
  if (f.downloadRun.size) f.abilities.add("downloads and runs code");
  return f;
}

const added = (a, b) => [...b].filter(x => !a.has(x)).sort();
/**
 * What the new version can do that the old one could not. `serious` holds the additions that
 * stand out on their own; the rest are listed for a reader.
 */
export function actionDiff(before, after) {
  const d = {
    abilities: added(before.abilities, after.abilities), hosts: added(before.hosts, after.hosts), programs: added(before.programs, after.programs),
    env: added(before.env, after.env), uses: added(new Set(before.uses), new Set(after.uses)),
    downloadRun: added(before.downloadRun, after.downloadRun),
    procMem: added(before.procMem, after.procMem),
    using: before.using !== after.using ? `${before.using} -> ${after.using}` : null,
    pre: !before.pre && after.pre, post: !before.post && after.post,
    tokenDefaults: Object.entries(after.inputs).filter(([k, v]) => /token/i.test(k) && /github\.token|secrets\./.test(v.default || "") && !(before.inputs[k]?.default || "").match(/github\.token|secrets\./)).map(([k]) => k),
  };
  d.secrets = d.env.filter(e => SECRETISH.test(e));
  d.serious = [
    ...d.downloadRun.map(x => `downloads and runs code: ${x}`), ...d.procMem.map(x => `reads the runner's process memory: ${x}`),
    ...d.secrets.map(x => `reads ${x}`), ...(d.pre ? ["a new pre step (runs before the job's own steps)"] : []), ...(d.post ? ["a new post step (runs after the job, even when it fails)"] : []),
    ...(d.using && /docker|composite/.test(d.using.split(" -> ")[1] || "") ? [`now runs as ${d.using.split(" -> ")[1]}`] : []), ...d.tokenDefaults.map(k => `input ${k} now defaults to a token`),
  ];
  d.any = d.serious.length + d.abilities.length + d.hosts.length + d.programs.length + d.env.length + d.uses.length > 0;
  return d;
}

// ---- fetching a version ----

const GH = () => ({ "user-agent": "vetcode", accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) });
/** A ref (tag, branch, SHA) to the commit SHA it points at now. */
export async function resolveRef(owner, repo, ref, { fetch: fetchFn = fetch } = {}) {
  if (/^[0-9a-f]{40}$/i.test(ref)) return ref.toLowerCase();
  const r = await fetchFn(`https://api.github.com/repos/${owner}/${repo}/commits/${encodeURIComponent(ref)}`, { headers: GH(), signal: AbortSignal.timeout(20000) });
  if (!r.ok) return null;
  return (await r.json()).sha || null;
}
/** One commit of an action, unpacked into a temporary folder. Nothing in it is run. */
export async function fetchAction(owner, repo, sha, { fetch: fetchFn = fetch, subpath = "" } = {}) {
  const { spawnSync } = await import("node:child_process");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-action-"));
  const cleanup = () => { spawnSync("chmod", ["-R", "u+rwX", dir]); fs.rmSync(dir, { recursive: true, force: true }); };
  const r = await fetchFn(`https://codeload.github.com/${owner}/${repo}/tar.gz/${sha}`, { headers: { "user-agent": "vetcode" }, signal: AbortSignal.timeout(120000) }).catch(() => null);
  if (!r?.ok) { cleanup(); return null; }
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > 200 << 20) { cleanup(); return null; }
  fs.writeFileSync(path.join(dir, "a.tgz"), buf);
  fs.mkdirSync(path.join(dir, "src"));
  spawnSync("tar", ["-xzf", path.join(dir, "a.tgz"), "-C", path.join(dir, "src"), "--no-same-owner"]);
  const top = fs.readdirSync(path.join(dir, "src"));
  const root = top.length === 1 ? path.join(dir, "src", top[0]) : path.join(dir, "src");
  return { root: subpath ? path.join(root, subpath) : root, cleanup };
}

/** Both versions of one action, profiled and compared. */
export async function diffAction(owner, repo, fromRef, toRef, { fetch: fetchFn = fetch, subpath = "" } = {}) {
  const [a, b] = await Promise.all([resolveRef(owner, repo, fromRef, { fetch: fetchFn }), resolveRef(owner, repo, toRef, { fetch: fetchFn })]);
  const base = { action: `${owner}/${repo}${subpath ? "/" + subpath : ""}`, from: fromRef, to: toRef, fromSha: a, toSha: b };
  if (!a || !b) return { ...base, error: `could not resolve ${!a ? fromRef : toRef}` };
  const [x, y] = await Promise.all([fetchAction(owner, repo, a, { fetch: fetchFn, subpath }), fetchAction(owner, repo, b, { fetch: fetchFn, subpath })]);
  try {
    if (!x || !y) return { ...base, error: "could not download it from GitHub" };
    const before = actionProfile(x.root), after = actionProfile(y.root);
    return { ...base, diff: actionDiff(before, after), using: after.using, files: after.files };
  } finally { x?.cleanup(); y?.cleanup(); }
}

/** The diff as Markdown, for the terminal and for a pull request comment. */
export function actionDiffMarkdown(results) {
  const out = ["### vetcode: what these action bumps add", ""];
  for (const r of results) {
    const head = `**${r.action}** ${r.from} → ${r.to}`;
    if (r.error) { out.push(`- ${head}: ${r.error}.`); continue; }
    const d = r.diff;
    if (!d.any) { out.push(`- ${head}: nothing new.`); continue; }
    out.push(`- ${head}${d.serious.length ? " ⚠️" : ""}: this bump adds`);
    for (const s of d.serious) out.push(`  - ${s}`);
    const list = (label, xs) => xs.length && out.push(`  - ${label}: ${xs.slice(0, 12).map(x => `\`${x}\``).join(", ")}${xs.length > 12 ? `, and ${xs.length - 12} more` : ""}`);
    list("abilities", d.abilities); list("hosts", d.hosts); list("programs", d.programs); list("environment names", d.env.filter(e => !d.secrets.includes(e))); list("actions it uses", d.uses);
  }
  out.push("", "Both versions were downloaded as source and read; nothing was installed or run. A new host or program is often a new feature: read the release notes against it.");
  return out.join("\n");
}
