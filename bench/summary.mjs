#!/usr/bin/env node
// Prints the latest benchmark result as a Markdown table (for the Actions run summary).
//   node bench/summary.mjs <results folder>
import fs from "node:fs";
import path from "node:path";

const dir = process.argv[2] || "bench/results";
const file = fs.readdirSync(dir).filter(f => /^\d{4}-\d\d-\d\d(\.shard\d+)?\.json$/.test(f)).sort().pop();
const { version, date, results } = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
const pct = x => (x * 100).toFixed(1) + "%";
console.log(`## vetcode ${version} benchmark (${date})\n`);
console.log("| Dataset | Malicious | Benign | Precision | Recall | F1 | False-positive rate |");
console.log("|---|---|---|---|---|---|---|");
for (const r of results) {
  const m = r.metrics.high;
  console.log(`| ${r.name} | ${r.samples.malicious} | ${r.samples.benign} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} | ${pct(m.fpr)} |`);
}
console.log("\nSigns: flagged when a malware, supply-chain or agent finding is high or critical (what the table above counts).");
if (results.some(r => r.metrics.verdict)) {
  console.log("\n| Dataset, verdict tier | Caught | False alarms | F1 |\n|---|---|---|---|");
  for (const r of results) { const m = r.metrics.verdict; if (m) console.log(`| ${r.name} | ${m.tp} of ${m.tp + m.fn} | ${m.fp} of ${m.fp + m.tn} | ${pct(m.f1)} |`); }
  console.log("\nVerdict: a rule with a measured record, two rules on one file, or a sign in a file an install script starts (lib/verdict.mjs).");
}
