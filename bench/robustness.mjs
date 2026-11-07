#!/usr/bin/env node
// Scores the evasion benchmark: of the samples a tool caught as they were, how many it still
// catches after each rewrite from mutate.mjs. Results come from run.mjs / rivals.mjs runs, one
// per mutation, written to <prefix>-<mutation>/.
//
//   node bench/robustness.mjs --mut <mutate.mjs out> --tool vetcode=<prefix> --tool guarddog=<prefix>
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const MUT = path.resolve(args[args.indexOf("--mut") + 1]);
const tools = args.flatMap((a, i) => a === "--tool" ? [args[i + 1].split("=")] : []);
const latest = dir => { const f = fs.readdirSync(dir).filter(x => /^\d{4}-\d\d-\d\d\.json$/.test(x)).sort().pop(); return JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")); };
const ids = (m, eco) => { const d = path.join(MUT, m, eco, "malicious"); return fs.existsSync(d) ? fs.readdirSync(d) : []; };
const mutations = fs.readdirSync(MUT).filter(m => m !== "none" && fs.statSync(path.join(MUT, m)).isDirectory());

const table = [];
for (const [tool, prefix] of tools) {
  const base = latest(`${prefix}-none`);
  for (const r of base.results) {
    const caught = new Set(ids("none", r.name).filter(id => !r.missed.includes(id)));
    const row = { tool, eco: r.name, verdict: r.metrics.high.verdict || "high", baseline: `${caught.size}/${ids("none", r.name).length}` };
    for (const m of mutations) {
      const res = latest(`${prefix}-${m}`).results.find(x => x.name === r.name);
      const kept = ids(m, r.name).filter(id => caught.has(id));
      const still = kept.filter(id => !res.missed.includes(id)).length;
      row[m] = kept.length ? `${(100 * still / kept.length).toFixed(1)}% (${still}/${kept.length})` : "–";
    }
    table.push(row);
  }
}
console.log(["tool", "eco", "verdict", "caught as is", ...mutations].join(" | "));
for (const r of table) console.log([r.tool, r.eco, r.verdict, r.baseline, ...mutations.map(m => r[m])].join(" | "));
fs.writeFileSync(path.join(MUT, "robustness.json"), JSON.stringify(table, null, 2));
