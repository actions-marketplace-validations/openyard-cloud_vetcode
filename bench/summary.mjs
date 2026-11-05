#!/usr/bin/env node
// Prints the latest benchmark result as a Markdown table (for the Actions run summary).
//   node bench/summary.mjs <results folder>
import fs from "node:fs";
import path from "node:path";

const dir = process.argv[2] || "bench/results";
const file = fs.readdirSync(dir).filter(f => f.endsWith(".json")).sort().pop();
const { version, date, results } = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
const pct = x => (x * 100).toFixed(1) + "%";
console.log(`## vetcode ${version} benchmark (${date})\n`);
console.log("| Dataset | Malicious | Benign | Precision | Recall | F1 | False-positive rate |");
console.log("|---|---|---|---|---|---|---|");
for (const r of results) {
  const m = r.metrics.high;
  console.log(`| ${r.name} | ${r.samples.malicious} | ${r.samples.benign} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} | ${pct(m.fpr)} |`);
}
console.log("\nVerdict: flagged when a malware, supply-chain or agent finding is high or critical.");
