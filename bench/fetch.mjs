#!/usr/bin/env node
// Downloads benchmark samples into a cache folder outside the repository. Nothing is
// installed, built or run: package archives are fetched as files and only read later.
//
//   node bench/fetch.mjs --cache <dir> [--npm 1000] [--pypi 300] [--seed 7]
//
// Sources
//   npm     NPMAnalysis benchmark (6,420 malicious / 7,288 benign npm packages), the same
//           data its paper used to score GuardDog and 12 other detectors.
//           https://github.com/lxyeternal/NPMAnalysis
//   pypi    malicious: Datadog malicious-software-packages-dataset (zip, password "infected")
//           benign: source distributions of widely used PyPI packages, from pypi.org
//   skills  malicious: Datadog dataset's AI-skills samples
//           benign: public skill collections (Anthropic, Trail of Bits, obra/superpowers)
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { POPULAR_PYPI } from "../skills/vetcode/scripts/lib/popular.mjs";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const CACHE = path.resolve(arg("--cache", path.join(process.env.TMPDIR || "/tmp", "vetcode-bench")));
const N_NPM = +arg("--npm", 1000), N_PYPI = +arg("--pypi", 300), SEED = +arg("--seed", 7);
const ONLY = arg("--only", "npm,pypi,skills").split(",");

// Seeded shuffle, so a run can be repeated on the same sample.
function rng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
const sample = (list, n, seed) => { const r = rng(seed), a = [...list]; for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a.slice(0, n); };

const GH = { "user-agent": "vetcode-bench", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };
async function getJson(url, headers = GH) { const r = await fetch(url, { headers }); if (!r.ok) throw new Error(`${r.status} ${url}`); return r.json(); }

async function download(jobs, label) {
  let done = 0, failed = 0;
  const queue = jobs.filter(j => !fs.existsSync(j.to));
  const worker = async () => {
    for (let j; (j = queue.shift()); ) {
      try {
        const r = await fetch(j.url, { headers: { "user-agent": "vetcode-bench" } });
        if (!r.ok) throw new Error(String(r.status));
        fs.mkdirSync(path.dirname(j.to), { recursive: true });
        fs.writeFileSync(j.to, Buffer.from(await r.arrayBuffer()));
        done++;
      } catch { failed++; }
    }
  };
  await Promise.all(Array.from({ length: 12 }, worker));
  console.error(`${label}: ${jobs.length - failed} ready (${done} downloaded now), ${failed} failed`);
}

async function npm() {
  // The file list comes from the GitHub API (two folders only); cloning the repository,
  // even without file contents, pulls the trees of tens of thousands of unpacked packages.
  const ds = await getJson("https://api.github.com/repos/lxyeternal/NPMAnalysis/contents/Dataset");
  const jobs = [];
  for (const [label, dir] of [["malicious", "zip_malware"], ["benign", "zip_benign"]]) {
    const tree = await getJson(`https://api.github.com/repos/lxyeternal/NPMAnalysis/git/trees/${ds.find(e => e.name === dir).sha}?recursive=1`);
    const all = tree.tree.filter(t => t.type === "blob" && t.path.endsWith(".tgz") && t.size < 20e6);
    console.error(`npm ${label}: ${all.length} available${tree.truncated ? " (list truncated by GitHub)" : ""}`);
    for (const t of sample(all, N_NPM, SEED)) jobs.push({ url: `https://raw.githubusercontent.com/lxyeternal/NPMAnalysis/HEAD/Dataset/${dir}/${t.path.split("/").map(encodeURIComponent).join("/")}`, to: path.join(CACHE, "npm", label, t.path.replaceAll("/", "__")) });
  }
  await download(jobs, "npm");
}

async function datadogTree(dir) {
  const root = await getJson("https://api.github.com/repos/DataDog/malicious-software-packages-dataset/contents/samples");
  const sha = root.find(e => e.name === dir).sha;
  return (await getJson(`https://api.github.com/repos/DataDog/malicious-software-packages-dataset/git/trees/${sha}?recursive=1`)).tree.filter(t => t.path.endsWith(".zip"));
}
const ddUrl = (dir, p) => `https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/${dir}/${p.split("/").map(encodeURIComponent).join("/")}`;

async function pypi() {
  const mal = sample(await datadogTree("pypi"), N_PYPI, SEED);
  await download(mal.map(t => ({ url: ddUrl("pypi", t.path), to: path.join(CACHE, "pypi", "malicious", t.path.split("/").pop()) })), "pypi malicious");
  const jobs = [];
  for (const name of [...POPULAR_PYPI].slice(0, N_PYPI)) {
    try {
      const meta = await getJson(`https://pypi.org/pypi/${name}/json`, { "user-agent": "vetcode-bench" });
      const sdist = meta.urls.find(u => u.packagetype === "sdist") || meta.urls.find(u => u.filename.endsWith(".whl"));
      if (sdist) jobs.push({ url: sdist.url, to: path.join(CACHE, "pypi", "benign", sdist.filename) });
    } catch {}
  }
  await download(jobs, "pypi benign");
}

async function skills() {
  const mal = await datadogTree("ai-skills");
  await download(mal.map(t => ({ url: ddUrl("ai-skills", t.path), to: path.join(CACHE, "skills", "malicious", t.path.split("/").pop()) })), "skills malicious");
  // Benign: whole public collections, split into one sample per skill folder at run time.
  const repos = ["anthropics/skills", "trailofbits/skills", "obra/superpowers"];
  await download(repos.map(r => ({ url: `https://codeload.github.com/${r}/tar.gz/HEAD`, to: path.join(CACHE, "skills", "benign-collections", r.replace("/", "__") + ".tar.gz") })), "skills benign");
}

// A second skills set that no rule was written from, and that nobody may look into (run.mjs
// refuses --explain on it): 157 skills found malicious in the wild on two skill marketplaces
// (MaliciousAgentSkillsBench, arXiv 2602.06547, packaged by the MaliciousSkillBench project),
// against four large public skill collections none of the rules were tuned on.
async function skillsHeldout() {
  await download([{ url: "https://raw.githubusercontent.com/protectskills/MaliciousSkillBench/main/packages/SRC002_packages.tar.gz", to: path.join(CACHE, "skills-heldout", "malicious-collections", "SRC002_packages.tar.gz") }], "skills-heldout malicious");
  const repos = ["github/awesome-copilot", "microsoft/skills", "wshobson/agents", "K-Dense-AI/scientific-agent-skills"];
  await download(repos.map(r => ({ url: `https://codeload.github.com/${r}/tar.gz/HEAD`, to: path.join(CACHE, "skills-heldout", "benign-collections", r.replace("/", "__") + ".tar.gz") })), "skills-heldout benign");
}

fs.mkdirSync(CACHE, { recursive: true });
// Stop early rather than fill the disk.
const freeGb = +spawnSync("df", ["-k", CACHE], { encoding: "utf8" }).stdout.trim().split("\n").pop().split(/\s+/)[3] / 1024 / 1024;
if (freeGb < 5) { console.error(`Only ${freeGb.toFixed(1)} GB free; need 5 GB. Nothing downloaded.`); process.exit(1); }
if (ONLY.includes("npm")) await npm();
if (ONLY.includes("pypi")) await pypi();
if (ONLY.includes("skills")) await skills();
if (ONLY.includes("skills-heldout")) await skillsHeldout();
console.error(`cache: ${CACHE}`);
