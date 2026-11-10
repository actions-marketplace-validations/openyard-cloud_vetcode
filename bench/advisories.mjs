#!/usr/bin/env node
// The agent step on real bugs: authorization and business-logic advisories from the GitHub
// Advisory Database, published after the model's training data ends. For each advisory the
// code before the fix (vulnerable) and at the fix (fixed) is reviewed the way a user would:
// Claude Code with vetcode loaded as a plugin, asked only for a security review.
//
//   node bench/advisories.mjs --limit 5                      # first five advisories
//   node bench/advisories.mjs --from 5 --limit 20 --jobs 2   # the next twenty
//   node bench/advisories.mjs --rescore                      # score saved answers again
//   node bench/advisories.mjs --plugin ../vetcode-0.3.1      # review with a pinned copy of vetcode
//   node bench/advisories.mjs --no-plugin --side bad --out bench/results/advisories-baseline
//                                                            # control: Claude Code alone, vulnerable code only
//
// Answers are saved per advisory in bench/results/advisories/, so a run that stops on a usage
// limit continues where it left off. bench/advisories.json lists the cases (see bench/README).
//
// Safety: the code is never built, installed or run. Only the folders the fix touched are
// fetched (sparse checkout, no history), agent instructions shipped with the target
// (.claude/, CLAUDE.md, AGENTS.md, .mcp.json) are removed, project settings are not loaded,
// and the agent may only read files and run the vetcode scanner.
//
// Scoring: the fix commit's diff marks where the bug is. A vulnerable case is caught when the
// agent reports (confirmed or likely, medium or above) a finding in a file the fix changed,
// within 20 lines of a changed hunk. A fixed case is a false alarm when the agent reports a
// finding in the same place on the fixed code. "In the right file" is reported as a looser
// second number.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const argv = process.argv;
const arg = (k, d) => { const i = argv.indexOf(k); return i > 0 ? argv[i + 1] : d; };
const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, "..");
const OUTDIR = path.resolve(arg("--out", path.join(here, "results/advisories")));
const FROM = +arg("--from", 0), LIMIT = +arg("--limit", 1e9), JOBS = +arg("--jobs", 1);
const MODEL = arg("--model", "");
const RESCORE = argv.includes("--rescore");
// What reviews: vetcode from this checkout (default), from another folder (--plugin, so editing
// the skill does not change a run in progress), or nothing at all (--no-plugin, the control).
const NO_PLUGIN = argv.includes("--no-plugin");
const PLUGIN = path.resolve(arg("--plugin", ROOT));
const SIDES = { bad: ["bad"], good: ["good"], both: ["bad", "good"] }[arg("--side", "both")];
if (!SIDES) throw new Error("--side is bad, good or both");
const REVIEWER = NO_PLUGIN ? "claude code alone" : `vetcode ${JSON.parse(fs.readFileSync(path.join(PLUGIN, "package.json"), "utf8")).version}`;
const NEAR = 20;
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const ALL = JSON.parse(fs.readFileSync(path.join(here, "advisories.json"), "utf8"));
const CASES = ALL.slice(FROM, FROM + LIMIT);
fs.mkdirSync(OUTDIR, { recursive: true });

// ---- ground truth from the fix diff -------------------------------------------------------
function hunks(c) {
  const cache = path.join(OUTDIR, `${c.ghsa}.diff.json`);
  if (fs.existsSync(cache)) return JSON.parse(fs.readFileSync(cache, "utf8"));
  const files = JSON.parse(execFileSync("gh", ["api", `repos/${c.repo}/commits/${c.fix}`, "--jq", "[.files[] | {f: .filename, p: .patch}]"], { encoding: "utf8", maxBuffer: 64 << 20 }));
  const out = {};
  for (const { f, p } of files) {
    if (!c.files.includes(f) || !p) continue;
    const old = [], neu = [];
    for (const m of p.matchAll(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/gm)) {
      old.push([+m[1], +m[1] + Math.max(+(m[2] ?? 1), 1) - 1]);
      neu.push([+m[3], +m[3] + Math.max(+(m[4] ?? 1), 1) - 1]);
    }
    out[f] = { old, neu };
  }
  fs.writeFileSync(cache, JSON.stringify(out));
  return out;
}

// ---- fetching only what is needed ---------------------------------------------------------
const AGENT_FILES = [".claude", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json", ".cursorrules", ".cursor", ".github/copilot-instructions.md", "GEMINI.md"];
function fetchAt(c, sha) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "review-"));
  const git = (...a) => execFileSync("git", ["-C", dir, ...a], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } });
  git("init", "-q");
  git("remote", "add", "origin", `https://github.com/${c.repo}.git`);
  git("sparse-checkout", "set", "--no-cone", `/${c.scope === "." ? "*" : c.scope + "/"}`);
  git("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", sha);
  git("-c", "core.hooksPath=/dev/null", "checkout", "-q", "FETCH_HEAD");
  fs.rmSync(path.join(dir, ".git"), { recursive: true, force: true });
  const strip = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (AGENT_FILES.includes(e.name) || AGENT_FILES.includes(path.relative(dir, p))) fs.rmSync(p, { recursive: true, force: true });
      else if (e.isDirectory()) strip(p);
    }
  };
  strip(dir);
  return dir;
}

// ---- the agent ----------------------------------------------------------------------------
const PROMPT = `Do a security review of the code in this folder before we ship it.

When you are done, end your reply with one JSON code block and nothing after it:
\`\`\`json
{"findings":[{"file":"path relative to this folder","line":1,"severity":"critical|high|medium|low","status":"confirmed|likely","title":"short title"}]}
\`\`\`
List only confirmed and likely findings. An empty list is a valid answer.`;

function review(dir) {
  const scanner = path.join(PLUGIN, "skills/vetcode/scripts/vet.mjs");
  const args = ["-p", PROMPT, "--output-format", "json", "--setting-sources", "user", "--strict-mcp-config", "--allowedTools", "Read", "Grep", "Glob"];
  if (!NO_PLUGIN) args.push("Skill", `Bash(node ${scanner}:*)`, `Bash(node "${scanner}":*)`, "--plugin-dir", PLUGIN);
  if (MODEL) args.push("--model", MODEL);
  return new Promise(resolve => {
    const p = spawn("claude", args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", d => out += d); p.stderr.on("data", d => err += d);
    const kill = setTimeout(() => p.kill("SIGTERM"), 30 * 60 * 1000);
    p.on("close", code => {
      clearTimeout(kill);
      let text = out, meta = {};
      try { const j = JSON.parse(out); text = j.result || ""; meta = { cost: j.total_cost_usd, turns: j.num_turns, ms: j.duration_ms, models: Object.keys(j.modelUsage || {}), error: j.is_error ? j.subtype || "error" : undefined }; } catch {}
      let findings = null;
      try { findings = JSON.parse([...text.matchAll(/```json\s*([\s\S]*?)```/g)].at(-1)[1]).findings; } catch {}
      const limited = !Array.isArray(findings) && /usage limit|limit reached|hit your [^.]*limit|out of extra usage|rate.limit/i.test(text.slice(-500) + err.slice(-500));
      resolve({ ok: Array.isArray(findings), findings: findings || [], ...meta, limited, code, tail: Array.isArray(findings) ? undefined : (err || text).slice(-300) });
    });
  });
}

// ---- scoring ------------------------------------------------------------------------------
const norm = f => (f || "").replace(/^\.?\//, "").replace(/^.*?\/review-[^/]+\//, "");
function score(c, diff, side, findings) {
  const ranges = Object.fromEntries(Object.entries(diff).map(([f, h]) => [f, side === "bad" ? h.old : h.neu]));
  const real = findings.filter(f => SEV[f.severity] >= 2 && f.status !== "false positive");
  const inFile = real.filter(f => ranges[norm(f.file)]);
  const near = inFile.filter(f => ranges[norm(f.file)].some(([a, b]) => +f.line >= a - NEAR && +f.line <= b + NEAR));
  return { near: near.length > 0, file: inFile.length > 0, total: real.length };
}

// ---- run ----------------------------------------------------------------------------------
async function runCase(c) {
  const file = path.join(OUTDIR, `${c.ghsa}.json`);
  const saved = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : {};
  const diff = hunks(c);
  for (const [side, sha] of [["bad", c.vulnerable], ["good", c.fix]]) {
    if (!SIDES.includes(side)) continue;
    if (RESCORE || saved[side]?.ok) continue;
    let dir;
    try { dir = fetchAt(c, sha); }
    catch (e) { saved[side] = { ok: false, tail: `fetch failed: ${String(e.stderr || e.message).slice(-200)}` }; continue; }
    const t0 = Date.now();
    saved[side] = { ...(await review(dir)), reviewer: REVIEWER };
    fs.rmSync(dir, { recursive: true, force: true });
    process.stderr.write(`${c.ghsa} ${side}: ${saved[side].ok ? saved[side].findings.length + " findings" : "no answer"} in ${((Date.now() - t0) / 60000).toFixed(1)} min${saved[side].limited ? " (usage limit)" : ""}\n`);
    fs.writeFileSync(file, JSON.stringify(saved, null, 1) + "\n");
    if (saved[side].limited) return { c, saved, diff, limited: true };
  }
  return { c, saved, diff };
}

const results = [];
let stop = false, i = 0;
await Promise.all(Array.from({ length: Math.min(JOBS, CASES.length) }, async () => {
  while (!stop && i < CASES.length) {
    const r = await runCase(CASES[i++]);
    results.push(r);
    if (r.limited) { stop = true; console.error("Usage limit reached: stopping. Run the same command later to continue."); }
  }
}));

// ---- report -------------------------------------------------------------------------------
const rows = results.filter(r => SIDES.every(s => r.saved[s]?.ok)).map(r => ({
  ...r, b: score(r.c, r.diff, "bad", r.saved.bad?.findings || []), g: score(r.c, r.diff, "good", r.saved.good?.findings || []) }));
rows.sort((x, y) => ALL.indexOf(x.c) - ALL.indexOf(y.c));
console.log(`\n| Advisory | Repo | Bug | Caught (near the fix) | In the file | Same place flagged on the fix | Findings bad / fixed |\n|---|---|---|---|---|---|---|`);
for (const r of rows) console.log(`| ${r.c.ghsa} | ${r.c.repo} | ${r.c.summary.replace(/\|/g, "/").slice(0, 70)} | ${r.b.near ? "yes" : "no"} | ${r.b.file ? "yes" : "no"} | ${r.g.near ? "yes" : "no"} | ${r.b.total} / ${r.g.total} |`);
const n = rows.length, k = f => rows.filter(f).length;
const all = rows.flatMap(r => [r.saved.bad, r.saved.good]);
const models = [...new Set(all.flatMap(a => a.models || []))];
console.log(`\n${n} advisories scored${results.length - n ? ` (${results.length - n} incomplete)` : ""}.`);
console.log(`Caught near the fix: ${k(r => r.b.near)}/${n}. Reported in a file the fix changed: ${k(r => r.b.file)}/${n}. Same place flagged on the fixed code: ${k(r => r.g.near)}/${n}.`);
console.log(`Models: ${models.join(", ") || "unknown"}. API-equivalent cost: $${all.reduce((s, a) => s + (a.cost || 0), 0).toFixed(2)} (not billed on a subscription). Median time per review: ${(all.map(a => a.ms || 0).sort((a, b) => a - b)[all.length >> 1] / 60000 || 0).toFixed(1)} min.`);
