#!/usr/bin/env node
// False alarms on real applications. The corpus (bench/noise.json) is a set of well-known,
// maintained open-source apps pinned to a commit. They handle tokens, passwords and API keys
// all day, so the words appear everywhere without any secret in the code. Whatever the
// scanner reports here at medium or above is presumed a false alarm until someone shows
// otherwise; the number to drive down is findings per repository, rule by rule.
//
//   node bench/noise.mjs                          # scan the corpus with this checkout
//   node bench/noise.mjs --out bench/results/<date>-noise.json
//   node bench/noise.mjs --baseline bench/results/<older>.json   # show what changed
//   node bench/noise.mjs --show secret-assignment               # print the lines of one rule
//
// No model and no cost: the scanner only. Repositories are fetched once (shallow, one commit)
// into bench/.cache/ and only read; nothing in them is installed, built or run.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const argv = process.argv, arg = (k, d) => { const i = argv.indexOf(k); return i > 0 ? argv[i + 1] : d; };
const here = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(arg("--scanner", path.join(here, "../skills/vetcode/scripts/vet.mjs")));
const CACHE = path.join(here, ".cache/noise");
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
// --corpus bench/noise-heldout.json: twelve other apps that no rule was tuned on, to check that
// what was learned on the first twelve holds elsewhere.
const CORPUS = JSON.parse(fs.readFileSync(path.resolve(arg("--corpus", path.join(here, "noise.json"))), "utf8")).filter(c => !arg("--only", "") || c.repo.includes(arg("--only")));

function checkout(c) {
  const dir = path.join(CACHE, `${c.repo.replace("/", "__")}@${c.sha.slice(0, 10)}`);
  if (fs.existsSync(path.join(dir, ".git"))) return dir;
  fs.mkdirSync(dir, { recursive: true });
  const git = (...a) => execFileSync("git", ["-C", dir, ...a], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } });
  git("init", "-q"); git("remote", "add", "origin", `https://github.com/${c.repo}.git`);
  git("fetch", "-q", "--depth", "1", "--filter=blob:limit=1m", "origin", c.sha);
  git("-c", "core.hooksPath=/dev/null", "checkout", "-q", "FETCH_HEAD");
  return dir;
}

const rows = [];
for (const c of CORPUS) {
  let dir; try { dir = checkout(c); } catch (e) { console.error(`${c.repo}: fetch failed: ${String(e.stderr || e.message).slice(-160)}`); continue; }
  const json = path.join(os.tmpdir(), `noise-${process.pid}.json`);
  spawnSync(process.execPath, [SCANNER, dir, "--no-tools", "--no-ignore", "--quiet", "--json", json], { stdio: "ignore", timeout: 10 * 60 * 1000 });
  if (!fs.existsSync(json)) { console.error(`${c.repo}: the scanner did not finish`); continue; }
  const r = JSON.parse(fs.readFileSync(json, "utf8")); fs.rmSync(json);
  const real = r.findings.filter(f => SEV[f.severity] >= 2);
  const by = k => real.reduce((m, f) => (m[f[k]] = (m[f[k]] || 0) + 1, m), {});
  // What decides the verdict of a pre-install check: a high or critical finding in the malware,
  // supply-chain or agent categories, low-confidence ones aside. On a clean app that is a wrong verdict.
  const flagged = [...new Set(r.findings.filter(f => ["malware", "supply-chain", "agent"].includes(f.category) && SEV[f.severity] >= 3 && f.confidence !== "low").map(f => f.rule))];
  rows.push({ repo: c.repo, sha: c.sha.slice(0, 10), files: r.stats?.files || 0, total: real.length, flagged, categories: by("category"), rules: by("rule") });
  const show = arg("--show", "");
  if (show) for (const f of r.findings.filter(f => f.rule === show)) console.log(`${c.repo} ${f.file}:${f.line} [${f.severity}] ${String(f.evidence || "").trim().slice(0, 140)}`);
}

const cats = ["secrets", "web", "malware", "supply-chain", "config"], sum = k => rows.reduce((n, r) => n + (r.categories[k] || 0), 0);
console.log(`\n| Repository | Files | Medium or above | ${cats.join(" | ")} |\n|---|---|---|${cats.map(() => "---").join("|")}|`);
for (const r of rows) console.log(`| ${r.repo} | ${r.files} | ${r.total} | ${cats.map(k => r.categories[k] || 0).join(" | ")} |`);
console.log(`| **${rows.length} repositories** | ${rows.reduce((n, r) => n + r.files, 0)} | **${rows.reduce((n, r) => n + r.total, 0)}** | ${cats.map(k => `**${sum(k)}**`).join(" | ")} |`);
const rules = {}; for (const r of rows) for (const [k, v] of Object.entries(r.rules)) rules[k] = (rules[k] || 0) + v;
const wrong = rows.filter(r => r.flagged.length);
console.log(`\nWrongly flagged as dangerous: ${wrong.length}/${rows.length}${wrong.length ? ` (${wrong.map(r => `${r.repo.split("/")[1]}: ${r.flagged.join(", ")}`).join("; ")})` : ""}.`);
console.log(`Noisiest rules: ${Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => `${k} ${v}`).join(", ")}.`);
const base = arg("--baseline", "");
if (base) {
  const old = JSON.parse(fs.readFileSync(base, "utf8")), was = {};
  for (const r of old.repos) for (const [k, v] of Object.entries(r.rules)) was[k] = (was[k] || 0) + v;
  const d = [...new Set([...Object.keys(rules), ...Object.keys(was)])].map(k => [k, (rules[k] || 0) - (was[k] || 0)]).filter(x => x[1]).sort((a, b) => a[1] - b[1]);
  console.log(`Against ${path.basename(base)}: ${old.repos.reduce((n, r) => n + r.total, 0)} → ${rows.reduce((n, r) => n + r.total, 0)}. ${d.map(([k, v]) => `${k} ${v > 0 ? "+" : ""}${v}`).join(", ") || "No change."}`);
}
const out = arg("--out", "");
if (out) fs.writeFileSync(out, JSON.stringify({ scanner: JSON.parse(fs.readFileSync(path.join(path.dirname(SCANNER), "../../../package.json"), "utf8")).version, repos: rows }, null, 1) + "\n");
