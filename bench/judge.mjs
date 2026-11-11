#!/usr/bin/env node
// A second, stricter score for bench/advisories.mjs: does a finding describe the advisory's
// bug? The first score only asks whether a finding sits within 20 lines of the fix, which can
// count an unrelated finding nearby and miss a correct one reported at another place.
//
//   node bench/judge.mjs                                         # judge bench/results/advisories
//   node bench/judge.mjs --out bench/results/advisories-baseline # judge another run
//
// A cheaper model reads the public advisory text and the findings (file, line, severity,
// title) and names the findings that describe the same vulnerability. Its verdicts are saved
// next to the answers as <ghsa>.judge.json and are not committed; check a sample by hand.
import fs from "node:fs";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const argv = process.argv, arg = (k, d) => { const i = argv.indexOf(k); return i > 0 ? argv[i + 1] : d; };
const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(arg("--out", path.join(here, "results/advisories")));
const TEXTS = path.join(here, "results/advisories");
const JUDGE = arg("--judge", "claude-sonnet-5-5"), JOBS = +arg("--jobs", 3), REDO = argv.includes("--redo");
const ALL = JSON.parse(fs.readFileSync(path.join(here, "advisories.json"), "utf8"));
const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function advisoryText(c) {
  const cache = path.join(TEXTS, `${c.ghsa}.advisory.json`);
  if (fs.existsSync(cache)) return JSON.parse(fs.readFileSync(cache, "utf8"));
  const t = JSON.parse(execFileSync("gh", ["api", `advisories/${c.ghsa}`, "--jq", "{summary, description}"], { encoding: "utf8", maxBuffer: 16 << 20 }));
  fs.writeFileSync(cache, JSON.stringify(t));
  return t;
}

function ask(prompt) {
  return new Promise(resolve => {
    const p = spawn("claude", ["-p", prompt, "--output-format", "json", "--model", JUDGE, "--effort", "low", "--tools", "", "--setting-sources", "user", "--strict-mcp-config"], { cwd: here, stdio: ["ignore", "pipe", "pipe"] });
    let out = ""; p.stdout.on("data", d => out += d);
    p.on("close", () => { try { const r = JSON.parse(out).result; resolve(JSON.parse(r.match(/\{[\s\S]*\}/)[0])); } catch { resolve(null); } });
  });
}

async function judge(c) {
  const file = path.join(OUT, `${c.ghsa}.json`), jf = path.join(OUT, `${c.ghsa}.judge.json`);
  if (!fs.existsSync(file)) return null;
  const s = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!s.bad?.ok) return null;
  if (!REDO && fs.existsSync(jf)) return { c, s, v: JSON.parse(fs.readFileSync(jf, "utf8")) };
  let v = { matches: [] };
  if (s.bad.findings.length) {
    const a = advisoryText(c);
    const r = await ask(`A security advisory describes one vulnerability. A reviewer, who had not seen the advisory, reported the findings below on the vulnerable code. Name the findings that describe the SAME vulnerability as the advisory: the same root cause in the same component or code path, so that fixing what the finding says would fix the advisory. A different bug in the same file does not count, and a vague or generic remark does not count.

ADVISORY: ${a.summary}
CWE: ${c.cwes.join(", ")}
Files the fix changed: ${c.files.join(", ")}
Description:
${String(a.description || "").slice(0, 2500)}

FINDINGS:
${s.bad.findings.map((f, i) => `${i}. [${f.severity}, ${f.status}] ${f.file}:${f.line} ${f.title}`).join("\n")}

Reply with JSON only: {"matches":[<numbers of the findings that describe the advisory's vulnerability, or empty>],"reason":"one sentence"}`);
    if (!r || !Array.isArray(r.matches)) { console.error(`${c.ghsa}: no verdict`); return null; }
    v = { matches: r.matches.filter(i => s.bad.findings[i]), reason: r.reason, judge: JUDGE };
  }
  fs.writeFileSync(jf, JSON.stringify(v, null, 1) + "\n");
  return { c, s, v };
}

const rows = []; let i = 0;
await Promise.all(Array.from({ length: JOBS }, async () => { while (i < ALL.length) { const r = await judge(ALL[i++]); if (r) rows.push(r); } }));
rows.sort((x, y) => ALL.indexOf(x.c) - ALL.indexOf(y.c));
const strict = r => r.v.matches.some(i => SEV[r.s.bad.findings[i].severity] >= 2), any = r => r.v.matches.length > 0;
console.log(`| Advisory | Repo | Describes the bug (medium or above) | Describes the bug (any severity) |\n|---|---|---|---|`);
for (const r of rows) console.log(`| ${r.c.ghsa} | ${r.c.repo} | ${strict(r) ? "yes" : "no"} | ${any(r) ? "yes" : "no"} |`);
console.log(`\n${rows.length} judged by ${JUDGE}. A finding describes the advisory's bug: ${rows.filter(strict).length}/${rows.length} at medium or above, ${rows.filter(any).length}/${rows.length} at any severity.`);
fs.writeFileSync(path.join(OUT, "judge-summary.json"), JSON.stringify(rows.map(r => ({ ghsa: r.c.ghsa, describes: strict(r), describesAnySeverity: any(r) })), null, 1) + "\n");
