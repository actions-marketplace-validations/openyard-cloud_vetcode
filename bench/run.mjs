#!/usr/bin/env node
// Scans every cached sample with vetcode and scores the verdicts.
//
//   node bench/run.mjs --cache <dir> [--out bench/results] [--only skills] [--explain] [--guard]
//
// Each archive is unpacked into its own empty folder, scanned read-only, and deleted.
// Verdict: a package is "flagged" when vetcode reports at least one finding at the chosen
// severity or worse in the malware, supply-chain or agent categories (web/config findings
// are vulnerabilities, not malice). Scored at two thresholds: high (default) and critical.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { vet, VERSION } from "../skills/vetcode/scripts/lib/index.mjs";
import { checkPackage } from "../skills/vetcode/scripts/lib/guard.mjs";
import { verdict } from "../skills/vetcode/scripts/lib/verdict.mjs";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const CACHE = path.resolve(arg("--cache", path.join(os.tmpdir(), "vetcode-bench")));
const OUT = path.resolve(arg("--out", "bench/results"));
const ONLY = arg("--only", "npm,pypi,skills").split(",");
// --shard i/n scores every n-th sample starting at i, so n processes can run side by side
// (merge their JSON with bench/merge.mjs).
const [SHARD, SHARDS] = arg("--shard", "0/1").split("/").map(Number);
const mine = list => list.filter((_, i) => i % SHARDS === SHARD);
const CATS = new Set(["malware", "supply-chain", "agent"]);
// --explain: for every malicious sample that was not flagged, record what it holds, so rules
// can be written without the sample leaving the runner: its files, the findings that fell
// short of the verdict, and the lines that mention downloads, secrets, shells or orders to
// an agent (cut to 220 characters; a description, not the sample).
const EXPLAIN = process.argv.includes("--explain");
const GUARD = process.argv.includes("--guard");
const TELL = /curl|wget|https?:\/\/|base64|\beval\b|\bexec\b|subprocess|os\.system|child_process|\.ssh|\.aws|\.env\b|token|secret|password|credential|api[_-]?key|ignore (?:all|any|previous|prior)|do not (?:tell|mention|reveal|inform|ask)|without (?:asking|telling|confirm|permission|notif)|silently|secretly|exfiltrat|upload|webhook|pastebin|ngrok|chmod|sudo|rm -rf|crontab|bashrc|zshrc|authorized_keys|keychain|wallet|system prompt|<!--|always run|before (?:doing|responding|anything|you)/i;
function explain(dir, res) {
  const files = [], lines = [];
  const walk = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (e.isFile()) files.push(p); } };
  try { walk(dir); } catch {}
  const size = f => { try { return fs.statSync(f).size; } catch { return -1; } }; // packages ship unreadable files
  for (const f of files) {
    if (size(f) < 0 || size(f) > 300000 || !/\.(md|txt|py|js|mjs|cjs|ts|sh|bash|json|ya?ml|toml|ps1|rb|go)$|(^|\/)[A-Z]+$/i.test(f)) continue;
    let text; try { text = fs.readFileSync(f, "utf8").split(/\r?\n/); } catch { continue; }
    const rel = path.relative(dir, f);
    if (/SKILL\.md$/i.test(f)) lines.push(...text.slice(0, 12).map((l, i) => `${rel}:${i + 1} ${l.slice(0, 220)}`));
    for (let i = 0; i < text.length && lines.length < 45; i++) if (TELL.test(text[i])) lines.push(`${rel}:${i + 1} ${text[i].trim().slice(0, 220)}`);
  }
  return { files: files.slice(0, 40).map(f => `${path.relative(dir, f)} (${size(f)})`), fileCount: files.length,
    below: res.findings.filter(f => RANK[f.severity] >= 2 || f.confidence === "low" || !CATS.has(f.category)).slice(0, 25).map(f => `${f.rule} ${f.severity}${f.confidence === "low" ? " (low confidence)" : ""} ${f.file}:${f.line}`), lines };
}
const explained = {};

// The guard's answer for each sample, as if an agent were about to install it on the day it
// was published and nobody had reported it yet: the registry lists the package, there is no
// advisory, and the release is past the waiting period. What is left is what the guard can see
// by itself: the name (a look-alike?) and the code in the archive. The registry and the
// advisory database are stand-ins built from the sample; nothing is fetched.
function identity(dir, eco, id) {
  const read = f => { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } };
  const find = (d, name, depth = 0) => { try { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isFile() && e.name === name) return p; if (e.isDirectory() && depth < 3) { const r = find(p, name, depth + 1); if (r) return r; } } } catch {} return null; };
  if (eco === "npm") { try { const j = JSON.parse(read(find(dir, "package.json") || "")); if (j.name) return { name: String(j.name).toLowerCase(), version: String(j.version || "1.0.0") }; } catch {} }
  else { const m = /^Name:\s*(\S+)[\s\S]*?^Version:\s*(\S+)/m.exec(read(find(dir, "PKG-INFO") || "")) || /name\s*=\s*["']([\w.-]+)["'][\s\S]{0,400}?version\s*=\s*["']([\w.]+)["']/.exec(read(find(dir, "setup.py") || "")); if (m) return { name: m[1].toLowerCase().replace(/[-_.]+/g, "-"), version: m[2] }; }
  const m = /^(?:\d{4}-\d\d-\d\d-)?(.+?)(?:[-_]v?(\d[\w.]*))?\.(?:zip|tgz|tar\.gz)$/.exec(id.split("__").pop());
  return { name: (m?.[1] || id).toLowerCase(), version: m?.[2] || "1.0.0" };
}
async function guardDecision(eco, it, res) {
  const { name, version } = identity(it.dir, eco, it.id), now = Date.now(), at = new Date(now - 30 * 86400000).toISOString();
  const reply = body => ({ status: 200, ok: true, json: async () => body });
  const fetchFn = async url => url.includes("api.osv.dev") ? reply({ vulns: [] })
    : eco === "npm" ? reply({ name, "dist-tags": { latest: version }, versions: { [version]: { name, version, dist: { tarball: "local", unpackedSize: 1 }, _npmUser: { name: "author" } } }, time: { [version]: at } })
    : reply({ info: { version }, urls: [{ packagetype: "sdist", url: "local", size: 1, upload_time_iso_8601: at }], releases: { [version]: [{ upload_time_iso_8601: at }] } });
  const r = await checkPackage({ eco, name, want: version }, { fetch: fetchFn, now, scan: async () => Object.assign(res.findings, { stats: res.stats }) });
  return r.decision;
}
const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Packages can ship read-only folders; make them writable so cleanup cannot stop the run.
function remove(dir) {
  spawnSync("chmod", ["-R", "u+rwX", dir]);
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 3 }); } catch { spawnSync("rm", ["-rf", dir]); }
}

function unpack(file, into) {
  fs.mkdirSync(into, { recursive: true });
  const r = file.endsWith(".zip")
    ? spawnSync("unzip", ["-qq", "-o", "-P", "infected", file, "-d", into])
    : spawnSync("tar", ["-xzf", file, "-C", into]);
  return r.status === 0 || fs.readdirSync(into).length > 0;
}

// One sample per skill folder (a directory holding SKILL.md) in the collections of a dataset.
function benignSkills(work, dataset = "skills", kind = "benign-collections") {
  const dir = path.join(CACHE, dataset, kind), out = [];
  if (!fs.existsSync(dir)) return out;
  for (const f of fs.readdirSync(dir)) {
    const into = path.join(work, `${dataset}-${kind}`, f);
    if (!unpack(path.join(dir, f), into)) continue;
    const walk = d => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) { if (fs.existsSync(path.join(p, "SKILL.md"))) out.push({ id: `${f}:${e.name}`, dir: p }); else walk(p); } } };
    walk(into);
  }
  return out;
}

async function score(name, items) {
  const rows = [];
  for (const it of items) {
    const res = await vet(it.dir, { tools: false, noIgnore: true });
    // Same as --fail-on: low-confidence findings (tests, docs) do not decide the verdict.
    const hits = res.findings.filter(f => CATS.has(f.category) && f.confidence !== "low");
    const worst = hits.reduce((m, f) => Math.min(m, RANK[f.severity]), 9);
    const decision = GUARD && !name.startsWith("skills") ? await guardDecision(name, it, res).catch(() => "error") : undefined;
    // Three ways to call a sample: any sign (the broad tier), a verdict (a trusted rule, or two rules on one file), and a verdict where the two rules may sit anywhere in the sample.
    const strict = verdict(res.findings).level, loose = verdict(res.findings, { anywhere: true }).level, placed = verdict(res.findings, { install: false }).level;
    rows.push({ id: it.id, label: it.label, worst, decision, strict, loose, placed, rules: [...new Set(hits.filter(f => RANK[f.severity] <= 1).map(f => f.rule))], files: res.stats.files });
    // The held-out set stays unseen: no description of its misses is ever written.
    if (EXPLAIN && name !== "skills-heldout" && it.label === "malicious" && worst > 1) (explained[name] ||= []).push({ id: it.id, ...explain(it.dir, res) });
    if (it.cleanup) remove(it.dir);
  }
  const metrics = {};
  for (const [t, max] of [["high", 1], ["critical", 0]]) {
    const tp = rows.filter(r => r.label === "malicious" && r.worst <= max).length, fn = rows.filter(r => r.label === "malicious" && r.worst > max).length;
    const fp = rows.filter(r => r.label === "benign" && r.worst <= max).length, tn = rows.filter(r => r.label === "benign" && r.worst > max).length;
    const p = tp / (tp + fp || 1), rcl = tp / (tp + fn || 1);
    metrics[t] = { tp, fn, fp, tn, precision: p, recall: rcl, f1: 2 * p * rcl / (p + rcl || 1), accuracy: (tp + tn) / rows.length, fpr: fp / (fp + tn || 1) };
  }
  for (const [t, key] of [["verdict", "strict"], ["verdictAnywhere", "loose"], ["verdictNoInstall", "placed"]]) {
    const tp = rows.filter(r => r.label === "malicious" && r[key]).length, fn = rows.filter(r => r.label === "malicious" && !r[key]).length;
    const fp = rows.filter(r => r.label === "benign" && r[key]).length, tn = rows.filter(r => r.label === "benign" && !r[key]).length;
    const p = tp / (tp + fp || 1), rcl = tp / (tp + fn || 1);
    metrics[t] = { tp, fn, fp, tn, precision: p, recall: rcl, f1: 2 * p * rcl / (p + rcl || 1), accuracy: (tp + tn) / rows.length, fpr: fp / (fp + tn || 1) };
  }
  const guard = GUARD && !name.startsWith("skills") ? Object.fromEntries(["malicious", "benign"].map(l => [l, Object.fromEntries(["deny", "ask", "allow", "error"].map(d => [d, rows.filter(r => r.label === l && r.decision === d).length]))])) : undefined;
  if (guard) console.error(`${name} guard: malicious ${JSON.stringify(guard.malicious)} · benign ${JSON.stringify(guard.benign)}`);
  // Per rule: how many samples it helped decide, and how many it decided alone. This is what says
  // which rules can be trusted to give a verdict by themselves and which need a second signal.
  const ruleStats = {};
  for (const r of rows) for (const id of r.rules) {
    const st = ruleStats[id] ||= { malicious: 0, maliciousAlone: 0, benign: 0, benignAlone: 0 };
    st[r.label]++; if (r.rules.length === 1) st[`${r.label}Alone`]++;
  }
  const ruleCount = label => Object.entries(rows.filter(r => r.label === label).flatMap(r => r.rules).reduce((m, k) => (m[k] = (m[k] || 0) + 1, m), {})).sort((a, b) => b[1] - a[1]);
  console.error(`${name}: ${rows.length} samples · F1 ${(metrics.high.f1 * 100).toFixed(1)}% (high) · ${(metrics.critical.f1 * 100).toFixed(1)}% (critical)`);
  return { name, samples: { malicious: rows.filter(r => r.label === "malicious").length, benign: rows.filter(r => r.label === "benign").length }, metrics, guard, ruleStats, rulesOnMalicious: ruleCount("malicious"), rulesOnBenign: ruleCount("benign"), missed: rows.filter(r => r.label === "malicious" && r.worst > 1).map(r => r.id), falseAlarms: rows.filter(r => r.label === "benign" && r.worst <= 1).map(r => ({ id: r.id, rules: r.rules })) };
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-bench-work-"));
const archives = (eco, label) => { const d = path.join(CACHE, eco, label); return fs.existsSync(d) ? mine(fs.readdirSync(d).sort()).map(f => ({ file: path.join(d, f), id: f, label })) : []; };
let seq = 0; // unique folder per sample across batches and datasets
const unpacked = list => list.map(a => { const dir = path.join(work, `${seq++}-${a.label}`); return unpack(a.file, dir) ? { id: a.id, label: a.label, dir, cleanup: true } : null; }).filter(Boolean);

const results = [];
for (const eco of ["npm", "pypi"].filter(e => ONLY.includes(e))) {
  const list = [...archives(eco, "malicious"), ...archives(eco, "benign")];
  if (!list.length) continue;
  // Unpack and scan in batches so the disk never holds the whole set at once.
  const items = [];
  for (let i = 0; i < list.length; i += 200) items.push(...unpacked(list.slice(i, i + 200)));
  results.push(await score(eco, items));
}
const skillItems = ONLY.includes("skills") ? [...unpacked(archives("skills", "malicious")), ...mine(benignSkills(work)).map(s => ({ ...s, label: "benign" }))] : [];
if (skillItems.length) results.push(await score("skills", skillItems));
if (ONLY.includes("skills-heldout")) {
  const held = [...mine(benignSkills(work, "skills-heldout", "malicious-collections")).map(s => ({ ...s, label: "malicious" })), ...mine(benignSkills(work, "skills-heldout", "benign-collections")).map(s => ({ ...s, label: "benign" }))];
  if (held.length) results.push(await score("skills-heldout", held));
}
remove(work);

fs.mkdirSync(OUT, { recursive: true });
const stamp = new Date().toISOString().slice(0, 10);
fs.writeFileSync(path.join(OUT, `${stamp}${SHARDS > 1 ? `.shard${SHARD}` : ""}.json`), JSON.stringify({ version: VERSION, date: stamp, results }, null, 2));
for (const [name, list] of Object.entries(explained)) fs.writeFileSync(path.join(OUT, `explain-${name}.json`), JSON.stringify(list, null, 1));
console.error(`results: ${path.join(OUT, stamp + ".json")}`);
