#!/usr/bin/env node
// GitHub Actions bump benchmark (--action-diff). Both versions of each action are downloaded as
// source tarballs and read; nothing is installed or run. No model.
//
//   node bench/actions.mjs --out <dir> [--real]
//
//   clean      the three most recent release-to-release bumps of 20 popular actions, chosen by
//              release date before scanning (issue #72). The question is how many get a
//              "this bump adds …" line, and how many a serious one.
//   stand-ins  the tj-actions/changed-files and reviewdog/action-setup changes, rebuilt from the
//              published analyses (bench/action-samples.mjs). In-sample by construction.
//   real       (--real, on a CI runner only) the malicious commits themselves, if GitHub still
//              serves them, against the release before.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { actionProfile, actionDiff, diffAction } from "../skills/vetcode/scripts/lib/actions.mjs";
import { TJ_ACTIONS, REVIEWDOG } from "./action-samples.mjs";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const OUT = path.resolve(arg("--out", "actions-results")), REAL = process.argv.includes("--real");
fs.mkdirSync(OUT, { recursive: true });
const GH = { "user-agent": "vetcode-bench", accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };

const ACTIONS = ["actions/checkout", "actions/setup-node", "actions/setup-python", "actions/setup-go", "actions/setup-java", "actions/cache", "actions/upload-artifact", "actions/download-artifact",
  "actions/github-script", "docker/login-action", "docker/build-push-action", "docker/setup-buildx-action", "docker/metadata-action", "aws-actions/configure-aws-credentials", "github/codeql-action",
  "peaceiris/actions-gh-pages", "softprops/action-gh-release", "codecov/codecov-action", "pnpm/action-setup", "actions/create-github-app-token"];

// The three most recent bumps: the four latest releases by date (not drafts, not pre-releases).
async function bumps(full) {
  const r = await fetch(`https://api.github.com/repos/${full}/releases?per_page=30`, { headers: GH });
  const list = (await r.json()).filter(x => !x.draft && !x.prerelease && /^v?\d/.test(x.tag_name)).sort((a, b) => b.published_at.localeCompare(a.published_at)).slice(0, 4).reverse();
  return list.slice(1).map((x, i) => ({ from: list[i].tag_name, to: x.tag_name }));
}

const flat = d => d && { ...d };
const clean = [];
for (const full of ACTIONS) {
  const [owner, repo] = full.split("/");
  let list = [];
  try { list = await bumps(full); } catch (e) { clean.push({ action: full, error: String(e.message || e) }); continue; }
  for (const b of list) {
    const res = await diffAction(owner, repo, b.from, b.to);
    clean.push({ action: full, from: b.from, to: b.to, error: res.error || null, using: res.using, diff: flat(res.diff) });
    console.error(`${full} ${b.from} -> ${b.to}: ${res.error || (res.diff.serious.length ? "SERIOUS" : res.diff.any ? "adds" : "nothing new")}`);
  }
}

const write = (files, dir) => { for (const [rel, text] of Object.entries(files)) { fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), text); } };
const standins = [];
for (const [name, pair] of [["tj-actions/changed-files", TJ_ACTIONS], ["reviewdog/action-setup", REVIEWDOG]]) {
  const a = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-sa-")), b = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-sb-"));
  write(pair.before, a); write(pair.after, b);
  const d = actionDiff(actionProfile(a), actionProfile(b));
  standins.push({ action: name, serious: d.serious, any: d.any });
  fs.rmSync(a, { recursive: true, force: true }); fs.rmSync(b, { recursive: true, force: true });
}

const real = [];
if (REAL) {
  if (!process.env.CI) { console.error("--real downloads malicious commits: it runs on a CI runner only"); process.exit(2); }
  // The tag before each compromise, and the malicious commit the tag was moved to (from the advisories).
  for (const [owner, repo, from, to] of [["tj-actions", "changed-files", "v45.0.7", "0e58ed8671d6b60d0890c21b07f8835ace038e67"], ["reviewdog", "action-setup", "v1.3.0", "f0d342d24037bb11d26b9bd8496e0808ba32e9ec"]]) {
    const res = await diffAction(owner, repo, from, to);
    real.push({ action: `${owner}/${repo}`, from, to, error: res.error || null, serious: res.diff?.serious || [], any: !!res.diff?.any });
  }
}

const ok = clean.filter(c => !c.error);
const summary = {
  clean: { bumps: ok.length, failed: clean.length - ok.length, anyAddition: ok.filter(c => c.diff.any).length, serious: ok.filter(c => c.diff.serious.length).map(c => `${c.action} ${c.from} -> ${c.to}: ${c.diff.serious.join("; ")}`),
    byKind: Object.fromEntries(["abilities", "hosts", "programs", "env", "uses", "secrets"].map(k => [k, ok.filter(c => c.diff[k]?.length).length])) },
  standins: standins.map(s => `${s.action}: ${s.serious.length ? "serious: " + s.serious.join("; ") : s.any ? "adds, nothing serious" : "nothing"}`),
  real: real.map(r => `${r.action} ${r.from} -> ${r.to.slice(0, 7)}: ${r.error || (r.serious.length ? "serious: " + r.serious.join("; ") : r.any ? "adds, nothing serious" : "nothing")}`),
};
summary.clean.anyRate = ok.length ? `${(summary.clean.anyAddition * 100 / ok.length).toFixed(1)}%` : "n/a";
summary.clean.seriousRate = ok.length ? `${(summary.clean.serious.length * 100 / ok.length).toFixed(1)}%` : "n/a";
fs.writeFileSync(path.join(OUT, "actions.json"), JSON.stringify({ summary, clean, standins, real }, null, 2));
console.log(JSON.stringify(summary, null, 2));
