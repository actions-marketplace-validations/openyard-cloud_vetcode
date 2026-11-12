#!/usr/bin/env node
// The scanner on real injection bugs. Each case is a reviewed advisory from the GitHub
// Advisory Database (cross-site scripting, SQL injection, command injection, SSRF, path
// traversal, open redirect, code injection, unsafe deserialization) with one fix commit. The
// lines that commit changed mark where the bug was. The files are scanned as they were before
// the fix and as they are after it, and the question is the one a reviewer has: did the
// scanner point at the place the maintainers later had to change, and did it stop pointing
// there once it was fixed?
//
//   node bench/injection.mjs collect [--per-class 60]   # build bench/injection.json from the advisory database
//   node bench/injection.mjs                             # scan every case, print the tables
//   node bench/injection.mjs --half check                # only the half no rule may be tuned on
//   node bench/injection.mjs --out bench/results/<date>-injection.json
//   node bench/injection.mjs --show GHSA-…               # what was found in one case, and where the fix is
//
// No model and no cost: the scanner only. Only the files the fix changed are fetched, at the
// two commits; nothing is cloned, installed, built or run.
//
// Two halves. Every case belongs to "tune" or "check" by its advisory id. Rules and their
// ranking may be adjusted on the tune half; the check half is only ever counted, and
// --show refuses it. The noise corpora taught this: every number measured on the set a rule
// was written from looked better than the first look at the next set.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { vet, VERSION } from "../skills/vetcode/scripts/lib/index.mjs";

const argv = process.argv, arg = (k, d) => { const i = argv.indexOf(k); return i > 0 ? argv[i + 1] : d; };
const here = path.dirname(fileURLToPath(import.meta.url));
const LIST = path.join(here, "injection.json");
const CACHE = path.join(here, ".cache/injection");
const NEAR = 3;
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// The bug classes, by the weakness ids advisories carry, and the rules that speak about each.
export const CLASSES = {
  xss: { cwes: [79, 80], rules: /^xss-|^template-|ssti|^dom-|postmessage/ },
  sqli: { cwes: [89, 564], rules: /^sql-|^nosql-|^orm-/ },
  command: { cwes: [78, 77, 88], rules: /^cmd-|^command-|shell|^code-eval|^exec-/ },
  ssrf: { cwes: [918], rules: /^ssrf-|^url-fetch|^request-/ },
  path: { cwes: [22, 23, 73], rules: /^path-|^zip-slip|traversal|^file-/ },
  redirect: { cwes: [601], rules: /redirect/ },
  code: { cwes: [94, 95, 1336], rules: /^code-|eval|ssti|template|^deserial|^cmd-/ },
  deserialize: { cwes: [502], rules: /deserial|pickle|yaml-load|unserialize|^code-/ },
};
const CODE = /\.(?:c?m?[jt]sx?|vue|svelte|astro|pyw?|php|phtml|rb|erb|go|java|kt|cs|cshtml|razor|rs|html?|ejs|hbs|handlebars|mustache|twig|jinja2?|j2|tpl|jsp|liquid|haml|slim|pug)$/i;
const NOT_CODE = /(^|\/)(tests?|__tests__|spec|specs|testing|testdata|fixtures?|e2e|cypress|playwright|docs?|examples?|samples?|benchmarks?|changelog|vendor|node_modules|dist|build|locales?|i18n)\/|\.(?:test|spec)\.\w+$|_test\.\w+$|(^|\/)test_[\w.-]+$|Tests?\.(?:java|cs|kt|php)$|\.min\.\w+$|\.d\.ts$/i;
const half = ghsa => parseInt(crypto.createHash("sha1").update(ghsa).digest("hex").slice(0, 2), 16) % 2 ? "check" : "tune";

const gh = (args, opts = {}) => execFileSync("gh", ["api", ...args], { encoding: "utf8", maxBuffer: 64 << 20, stdio: ["ignore", "pipe", "pipe"], ...opts });

// ---- collect --------------------------------------------------------------------------------

/** The lines of the old file that the patch removed or, for a pure insertion, the line it was inserted after. */
export function marks(patch) {
  const old = [], neu = [];
  let a = 0, b = 0;
  for (const line of String(patch).split("\n")) {
    const h = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
    if (h) { a = +h[1]; b = +h[2]; continue; }
    if (line.startsWith("\\")) continue;
    if (line.startsWith("-")) { old.push(a); neu.push(b); a++; }
    else if (line.startsWith("+")) { neu.push(b); old.push(Math.max(1, a - 1)); b++; }
    else { a++; b++; }
  }
  return { old: [...new Set(old)].sort((x, y) => x - y), new: [...new Set(neu)].sort((x, y) => x - y) };
}

function collect() {
  const perClass = +arg("--per-class", 60), pages = +arg("--pages", 6);
  const have = fs.existsSync(LIST) ? JSON.parse(fs.readFileSync(LIST, "utf8")) : [];
  const seen = new Set(have.map(c => c.ghsa)), out = [...have];
  const count = cls => out.filter(c => c.class === cls).length;
  for (const [cls, { cwes }] of Object.entries(CLASSES)) {
    let url = `advisories?type=reviewed&per_page=100&sort=published&direction=desc&cwes=${cwes.join(",")}`;
    for (let p = 0; p < pages && url && count(cls) < perClass; p++) {
      const raw = gh(["-i", url]);
      const split = raw.indexOf("\n\n") > 0 && raw.indexOf("\r\n\r\n") < 0 ? raw.indexOf("\n\n") : raw.indexOf("\r\n\r\n");
      const head = raw.slice(0, split), list = JSON.parse(raw.slice(split).trim());
      url = (/<https:\/\/api\.github\.com\/([^>]+)>;\s*rel="next"/.exec(head) || [])[1] || null;
      for (const a of list) {
        if (count(cls) >= perClass) break;
        if (seen.has(a.ghsa_id) || a.withdrawn_at) continue;
        const commits = [...new Set((a.references || []).map(r => /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/commit\/([0-9a-f]{12,40})\b/.exec(r)).filter(Boolean).map(m => `${m[1]}@${m[2]}`))];
        // One fix commit says where the bug was. Several commits are backports or a series; a guess at which one would be mine.
        if (commits.length !== 1) continue;
        const [repo, sha] = commits[0].split("@");
        let c;
        try { c = JSON.parse(gh([`repos/${repo}/commits/${sha}`])); } catch { continue; }
        if ((c.parents || []).length !== 1) continue;
        const files = (c.files || []).filter(f => CODE.test(f.filename) && !NOT_CODE.test(f.filename));
        // The bug has to be in code that existed before the fix, in a change small enough to point at it.
        if (!files.length || files.length > 6 || files.some(f => f.status !== "modified" || !f.patch)) continue;
        if (files.reduce((n, f) => n + f.changes, 0) > 300) continue;
        seen.add(a.ghsa_id);
        out.push({
          ghsa: a.ghsa_id, class: cls, half: half(a.ghsa_id), cwes: (a.cwes || []).map(w => w.cwe_id), severity: a.severity,
          eco: [...new Set((a.vulnerabilities || []).map(v => v.package?.ecosystem).filter(Boolean))].join(","), published: (a.published_at || "").slice(0, 10),
          summary: a.summary, repo, fix: c.sha, vulnerable: c.parents[0].sha,
          files: files.map(f => ({ path: f.filename, ...marks(f.patch) })),
        });
        process.stderr.write(`${cls} ${count(cls)}/${perClass}  ${a.ghsa_id}  ${repo}\n`);
      }
    }
  }
  fs.writeFileSync(LIST, JSON.stringify(out, null, 1) + "\n");
  console.log(`${out.length} cases: ${Object.keys(CLASSES).map(k => `${k} ${count(k)}`).join(", ")}; tune ${out.filter(c => c.half === "tune").length}, check ${out.filter(c => c.half === "check").length}`);
}

// ---- run ------------------------------------------------------------------------------------

async function source(c, side, file) {
  const sha = side === "bad" ? c.vulnerable : c.fix;
  const to = path.join(CACHE, c.ghsa, side, file);
  if (fs.existsSync(to)) return true;
  const r = await fetch(`https://raw.githubusercontent.com/${c.repo}/${sha}/${file.split("/").map(encodeURIComponent).join("/")}`, { signal: AbortSignal.timeout(30000) });
  if (!r.ok) return false;
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > 2 << 20) return false;
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.writeFileSync(to, buf);
  return true;
}

async function scan(c, side) {
  for (const f of c.files) if (!(await source(c, side, f.path))) return null;
  const dir = path.join(CACHE, c.ghsa, side);
  // The cache sits inside this repository and is ignored by it; a repository of its own makes the scanner read the files.
  if (!fs.existsSync(path.join(dir, ".git"))) execFileSync("git", ["-C", dir, "init", "-q"], { stdio: "ignore" });
  const res = await vet(dir, { tools: false, noIgnore: true, log: () => {} });
  return res.findings.map(f => ({ rule: f.rule, category: f.category, severity: f.severity, confidence: f.confidence, file: f.file, line: f.line }));
}

const nearest = (lines, n) => lines.reduce((best, l) => Math.min(best, Math.abs(l - n)), Infinity);

async function run() {
  const all = JSON.parse(fs.readFileSync(LIST, "utf8"));
  const only = arg("--half", ""), show = arg("--show", "");
  if (show) {
    const c = all.find(x => x.ghsa === show);
    if (!c) throw new Error(`no case ${show}`);
    if (c.half === "check") throw new Error(`${show} is in the check half: it is counted, never looked at.`);
    const bad = await scan(c, "bad"), good = await scan(c, "good");
    console.log(`${c.ghsa} ${c.class} ${c.repo}\n${c.summary}\nfix ${c.fix.slice(0, 10)}, files:`);
    for (const f of c.files) console.log(`  ${f.path}  changed lines (before the fix): ${f.old.join(",")}`);
    console.log("before the fix:"); for (const f of bad || []) console.log(`  ${f.severity} ${f.rule} ${f.file}:${f.line}`);
    console.log("after the fix:"); for (const f of good || []) console.log(`  ${f.severity} ${f.rule} ${f.file}:${f.line}`);
    return;
  }
  const cases = all.filter(c => !only || c.half === only);
  const rows = [];
  for (const c of cases) {
    const bad = await scan(c, "bad").catch(() => null), good = bad && await scan(c, "good").catch(() => null);
    if (!bad || !good) { process.stderr.write(`${c.ghsa}: source not available, left out\n`); continue; }
    const cls = CLASSES[c.class];
    const at = (findings, key) => findings.filter(f => c.files.some(x => x.path === f.file && nearest(x[key], f.line) <= NEAR));
    const nearBad = at(bad, "old"), nearGood = at(good, "new");
    const inFile = bad.filter(f => c.files.some(x => x.path === f.file));
    const top = fs => fs.reduce((m, f) => Math.max(m, SEV[f.severity]), -1);
    const rightKind = nearBad.filter(f => cls.rules.test(f.rule));
    // Gone after the fix: a rule that pointed at the bug and no longer points at the same place.
    const gone = rightKind.filter(f => !nearGood.some(g => g.rule === f.rule && g.file === f.file));
    rows.push({ ghsa: c.ghsa, class: c.class, half: c.half, repo: c.repo, eco: c.eco, ext: [...new Set(c.files.map(f => path.extname(f.path).toLowerCase()))].join(","),
      near: top(nearBad), kind: top(rightKind), file: top(inFile), stillAfter: rightKind.length > 0 && gone.length === 0,
      rules: [...new Set(rightKind.map(f => f.rule))], otherRules: [...new Set(nearBad.filter(f => !cls.rules.test(f.rule)).map(f => f.rule))] });
  }
  const pct = (n, d) => d ? `${n}/${d} (${Math.round(n * 100 / d)}%)` : "0/0";
  const table = (title, groups) => {
    console.log(`\n${title}\n\n| | Cases | Right kind of finding at the fix, medium or above | …any severity | Any finding at the fix | Any finding in a changed file | Still flagged after the fix |\n|---|---|---|---|---|---|---|`);
    for (const [name, rs] of groups) {
      if (!rs.length) continue;
      const k2 = rs.filter(r => r.kind >= 2).length, k0 = rs.filter(r => r.kind >= 0).length;
      console.log(`| ${name} | ${rs.length} | ${pct(k2, rs.length)} | ${pct(k0, rs.length)} | ${pct(rs.filter(r => r.near >= 0).length, rs.length)} | ${pct(rs.filter(r => r.file >= 0).length, rs.length)} | ${pct(rs.filter(r => r.stillAfter).length, k0)} |`);
    }
  };
  console.log(`vetcode ${VERSION}, ${rows.length} cases, a finding counts when it is within ${NEAR} lines of a line the fix changed.`);
  table("By half", [["all", rows], ["tune", rows.filter(r => r.half === "tune")], ["check", rows.filter(r => r.half === "check")]]);
  table("By class", Object.keys(CLASSES).map(k => [k, rows.filter(r => r.class === k)]));
  const exts = [...new Set(rows.map(r => r.ext.split(",")[0]))].map(e => [e, rows.filter(r => r.ext.split(",")[0] === e)]).filter(([, rs]) => rs.length >= 5).sort((a, b) => b[1].length - a[1].length);
  table("By language of the first changed file (5 cases or more)", exts);
  // Which rules point at real bugs: the tune half only, so that ranking rules on it stays honest.
  const hits = {};
  for (const r of rows.filter(r => r.half === "tune")) for (const id of r.rules) hits[id] = (hits[id] || 0) + 1;
  console.log(`\nRules that pointed at a real bug (tune half): ${Object.entries(hits).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}`);
  const out = arg("--out", "");
  if (out) {
    fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
    const sum = rs => ({ cases: rs.length, rightKindMedium: rs.filter(r => r.kind >= 2).length, rightKind: rs.filter(r => r.kind >= 0).length, anyAtFix: rs.filter(r => r.near >= 0).length, anyInFile: rs.filter(r => r.file >= 0).length, stillAfterFix: rs.filter(r => r.stillAfter).length });
    const byClass = rs => Object.fromEntries(Object.keys(CLASSES).map(k => [k, sum(rs.filter(r => r.class === k))]));
    // The check half is stored as totals only: which of its cases were missed is not something to look up.
    fs.writeFileSync(out, JSON.stringify({ scanner: VERSION, near: NEAR, all: sum(rows), tune: { ...sum(rows.filter(r => r.half === "tune")), byClass: byClass(rows.filter(r => r.half === "tune")) },
      check: { ...sum(rows.filter(r => r.half === "check")), byClass: byClass(rows.filter(r => r.half === "check")) }, ruleHitsOnTune: hits, tuneCases: rows.filter(r => r.half === "tune") }, null, 1) + "\n");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (argv[2] === "collect") collect(); else await run();
}
