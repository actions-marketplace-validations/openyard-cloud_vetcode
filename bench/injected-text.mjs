#!/usr/bin/env node
// Would the patterns for poisoned instruction files also catch instructions injected into text an
// agent receives from outside (a web page, a tool's answer)? A check before building a guard for
// tool results: two public injection sets, and the documents of the clean applications as the clean side.
//
//   node bench/injected-text.mjs
//
// No model and no cost. The sets are fetched once into bench/.cache/injected-text/ and only read
// as text; they quote instructions written to steer an agent, so read any output as untrusted.
//   InjecAgent (uiuc-kang-lab): tool answers that carry an attacker's instruction, plain ("base")
//     and wrapped in a fixed "ignore all previous instructions" sentence ("enhanced").
//   deepset/prompt-injections: 662 short prompts, labelled injection or not.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scanAgentFiles } from "../skills/vetcode/scripts/lib/agent.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const CACHE = path.join(here, ".cache/injected-text");
async function get(name, url) {
  const to = path.join(CACHE, name);
  if (!fs.existsSync(to)) {
    const r = await fetch(url, { signal: AbortSignal.timeout(60000) });
    if (!r.ok) throw new Error(`${url}: ${r.status}`);
    fs.mkdirSync(path.dirname(to), { recursive: true });
    fs.writeFileSync(to, Buffer.from(await r.arrayBuffer()));
  }
  return JSON.parse(fs.readFileSync(to, "utf8"));
}
// The same reader that reads CLAUDE.md and skills, at the severity that counts as a sign.
const flagged = text => { const out = []; scanAgentFiles({ rel: "CLAUDE.md" }, String(text), out); return out.some(f => f.severity === "high" || f.severity === "critical"); };
const row = (name, texts) => { const n = texts.filter(flagged).length; console.log(`| ${name} | ${texts.length} | ${n} (${(n * 100 / Math.max(1, texts.length)).toFixed(1)}%) |`); };

console.log("| Text | Items | Flagged |\n|---|---|---|");
for (const f of ["dh_base", "ds_base", "dh_enhanced", "ds_enhanced"]) {
  const cases = await get(`injecagent-${f}.json`, `https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/test_cases_${f}.json`);
  row(`InjecAgent ${f.replace("_", ", ")}: tool answers with an injected instruction`, cases.map(c => c["Tool Response"] || ""));
}
const rows = [];
for (const [split, offsets] of [["train", [0, 100, 200, 300, 400, 500]], ["test", [0, 100]]]) for (const o of offsets) {
  rows.push(...(await get(`deepset-${split}-${o}.json`, `https://datasets-server.huggingface.co/rows?dataset=deepset%2Fprompt-injections&config=default&split=${split}&offset=${o}&length=100`)).rows.map(r => r.row));
}
row("deepset prompt-injections: labelled injection", rows.filter(r => r.label === 1).map(r => r.text));
row("deepset prompt-injections: labelled not an injection", rows.filter(r => r.label === 0).map(r => r.text));
// The clean side: documents of the applications bench/noise.mjs has fetched.
const apps = path.join(here, ".cache/noise"), docs = [];
if (fs.existsSync(apps)) for (const d of fs.readdirSync(apps)) {
  const root = path.join(apps, d);
  if (!fs.existsSync(path.join(root, ".git"))) continue;
  for (const rel of spawnSync("git", ["ls-files", "-z", "*.md", "*.mdx", "*.rst"], { cwd: root, encoding: "utf8", maxBuffer: 64 << 20 }).stdout.split("\0").filter(Boolean)) {
    try { const st = fs.statSync(path.join(root, rel)); if (st.size >= 200 && st.size <= 300000) docs.push(fs.readFileSync(path.join(root, rel), "utf8")); } catch {}
  }
}
if (docs.length) row("Documents of the clean applications (run bench/noise.mjs first)", docs);
