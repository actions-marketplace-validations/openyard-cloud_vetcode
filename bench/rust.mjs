#!/usr/bin/env node
// Rust benchmark: build scripts and proc macros. Crates are downloaded from crates.io as .crate
// archives and read; nothing is built or run.
//
//   node bench/rust.mjs --out <dir> [--top 200] [--from 0] [--no-lookalikes] [--real]
//
//   clean      the --top most downloaded crates on crates.io, plus look-alikes whose build
//              scripts legitimately compile C, start protoc or clang, read git or env vars, or
//              download a prebuilt library. A verdict on any of them is a false alarm.
//   stand-ins  the proc-macro1 dropper and the onering exfiltrator, rebuilt from the published
//              analyses (bench/rust-samples.mjs), as they are and rewritten the ways attackers
//              hide strings: concat!, character codes, reversed literals, include_str! of an
//              encoded file. Each must keep its verdict.
//   real       (--real, on a CI runner only) the malicious releases crates.io still serves, run
//              through --cargo-diff against the release before. Today that is append-only-vec
//              0.1.9; arrayref 0.3.10, internment 0.8.7, proc-macro1, proc-macro-en and onering
//              1.4.1 were removed, so their code cannot be measured.
import fs from "node:fs";
import path from "node:path";
import { vet } from "../skills/vetcode/scripts/lib/index.mjs";
import { fetchCrate, cargoDiff, cargoDiffMarkdown } from "../skills/vetcode/scripts/lib/rust.mjs";
import { PROC_MACRO1, ONERING } from "./rust-samples.mjs";

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const OUT = path.resolve(arg("--out", "rust-results")), TOP = +arg("--top", 200), FROM = +arg("--from", 0), REAL = process.argv.includes("--real");
const WITH_LOOKALIKES = !process.argv.includes("--no-lookalikes");
const UA = { headers: { "User-Agent": "vetcode-bench (github.com/openyard-cloud/vetcode)" } };
fs.mkdirSync(OUT, { recursive: true });

const LOOKALIKES = ["cc", "cmake", "bindgen", "prost-build", "tonic-build", "openssl-sys", "ring", "pyo3-build-config", "vergen", "vergen-gitcl", "built", "shadow-rs", "git-version",
  "ort-sys", "onnxruntime-sys", "protobuf-src", "protoc-bin-vendored", "libz-sys", "zstd-sys", "libgit2-sys", "tikv-jemalloc-sys", "librocksdb-sys", "aws-lc-sys", "boring-sys", "rusty_v8", "tch", "torch-sys", "openblas-src", "intel-mkl-src", "rdkafka-sys"];

// Crates ranked FROM+1 to FROM+n by all-time downloads: --from 200 is a second, untouched set.
async function topCrates(n) {
  const names = [];
  for (let page = Math.floor(FROM / 100) + 1; names.length < n + (FROM % 100); page++) {
    const r = await fetch(`https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=${page}`, UA);
    const d = await r.json();
    if (!d.crates?.length) break;
    names.push(...d.crates.map(c => c.name));
    await new Promise(r => setTimeout(r, 1100)); // crates.io asks for one request a second
  }
  return names.slice(FROM % 100, FROM % 100 + n);
}
const latest = async name => { const d = await (await fetch(`https://crates.io/api/v1/crates/${name}`, UA)).json(); return d.crate?.max_stable_version || d.crate?.max_version; };

const SIGN = f => ["malware", "supply-chain", "agent"].includes(f.category) && f.confidence !== "low" && ["critical", "high"].includes(f.severity);
async function scanDir(root, name) {
  const r = await vet(root, { tools: false, noIgnore: true, places: false, log: () => {} });
  const crate = r.profiles.find(p => p.kind === "crate" && (!name || p.name === name)) || r.profiles.find(p => p.kind === "crate");
  return { verdict: r.verdict.level, decided: r.verdict.decided.map(f => f.rule), signs: r.findings.filter(SIGN).map(f => `${f.rule} ${f.file}:${f.line}`),
    rustFindings: r.findings.filter(f => f.rule.startsWith("rust-")).map(f => `${f.severity} ${f.rule} ${f.file}:${f.line}`),
    buildScript: crate?.buildTime?.buildScript || null, procMacro: !!crate?.buildTime?.procMacro, buildTime: Object.keys(crate?.buildTime?.capabilities || {}), files: r.stats.files };
}

// ---- clean ----
const clean = [];
const names = [...new Set([...(TOP ? await topCrates(TOP) : []), ...(WITH_LOOKALIKES ? LOOKALIKES : [])])];
console.error(`clean: ${names.length} crates`);
for (const [i, name] of names.entries()) {
  try {
    const v = await latest(name);
    const c = v && await fetchCrate(name, v);
    if (!c) { clean.push({ name, error: "download failed" }); continue; }
    try { clean.push({ name, version: v, lookalike: LOOKALIKES.includes(name), ...(await scanDir(c.root, name)) }); } finally { c.cleanup(); }
  } catch (e) { clean.push({ name, error: String(e.message || e) }); }
  if (i % 20 === 19) console.error(`  ${i + 1}/${names.length}`);
  await new Promise(r => setTimeout(r, 300));
}

// ---- stand-ins and their rewrites ----
const lit = /"([^"\\\n]{4,200})"/g;
const eachLiteral = (text, fn) => text.split("\n").map(l => /^\s*(?:use|mod|#\[|\/\/)/.test(l) ? l : l.replace(lit, (m, s) => fn(s, m))).join("\n");
const MUTATIONS = {
  none: f => f,
  concat: f => ({ ...f, "build.rs": eachLiteral(f["build.rs"], s => `concat!(${JSON.stringify(s.slice(0, s.length >> 1))}, ${JSON.stringify(s.slice(s.length >> 1))})`) }),
  charcode: f => ({ ...f, "build.rs": eachLiteral(f["build.rs"], (s, m) => /^[\x20-\x7e]+$/.test(s) ? `&String::from_utf8(vec![${[...s].map(c => c.charCodeAt(0)).join(", ")}]).unwrap()` : m) }),
  reverse: f => ({ ...f, "build.rs": eachLiteral(f["build.rs"], s => `&${JSON.stringify([...s].reverse().join(""))}.chars().rev().collect::<String>()`) }),
  // Every literal moved into an encoded file that the build script includes and decodes.
  include: f => {
    const strings = [];
    const body = eachLiteral(f["build.rs"], s => { strings.push(s); return `&S[${strings.length - 1}]`; });
    const blob = Buffer.from(strings.join("\n")).toString("base64");
    return { ...f, "data.b64": blob, "build.rs": `use base64::Engine;\nstatic S: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| String::from_utf8(base64::engine::general_purpose::STANDARD.decode(include_str!("data.b64").trim()).unwrap()).unwrap().lines().map(String::from).collect());\n${body}` };
  },
};
const standins = [];
for (const [name, files] of [["proc-macro1", PROC_MACRO1], ["onering", ONERING]]) for (const [m, fn] of Object.entries(MUTATIONS)) {
  const dir = fs.mkdtempSync(path.join(OUT, "standin-"));
  for (const [rel, text] of Object.entries(fn(files))) { fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), text); }
  try { standins.push({ name, mutation: m, ...(await scanDir(dir, name)) }); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// ---- real (CI only) ----
const real = [];
if (REAL) {
  if (!process.env.CI) { console.error("--real downloads malicious releases: it runs on a CI runner only"); process.exit(2); }
  const src = "registry+https://github.com/rust-lang/crates.io-index";
  const lock = pkgs => "version = 4\n" + pkgs.map(([n, v, deps = []]) => `\n[[package]]\nname = "${n}"\nversion = "${v}"\nsource = "${src}"\ndependencies = [${deps.map(d => `"${d}"`).join(", ")}]\n`).join("");
  // The update a user would have taken on 2026-08-20: the dependency on the typosquat came with it.
  for (const [name, from, to, added] of [["append-only-vec", "0.1.8", "0.1.9", [["proc-macro1", "1.0.107"]]], ["arrayref", "0.3.9", "0.3.10", [["proc-macro1", "1.0.107"]]], ["internment", "0.8.6", "0.8.7", [["proc-macro1", "1.0.107"]]]]) {
    const d = await cargoDiff(lock([[name, from]]), lock([[name, to, added.map(a => a[0])], ...added]), { vet });
    real.push({ update: `${name} ${from} -> ${to}`, level: d.level, crates: d.crates.map(c => ({ name: c.name, to: c.to, status: c.status, level: c.level, error: c.error || null, requiredBy: c.requiredBy, abilities: c.abilities, gained: c.gained, verdict: c.verdict })), report: cargoDiffMarkdown(d) });
  }
}

// ---- summary ----
const ok = clean.filter(c => !c.error);
const summary = {
  clean: { crates: ok.length, failed: clean.length - ok.length, verdicts: ok.filter(c => c.verdict).map(c => `${c.name} ${c.version}: ${c.decided.join(", ")}`),
    withSigns: ok.filter(c => c.signs.length).length, buildScripts: ok.filter(c => c.buildScript).length, procMacros: ok.filter(c => c.procMacro).length,
    worthALook: ok.filter(c => c.rustFindings.some(f => f.startsWith("medium rust-build-time"))).map(c => c.name),
    buildTimeNetwork: ok.filter(c => c.buildTime.includes("uses the network")).map(c => c.name) },
  standins: standins.map(s => ({ name: s.name, mutation: s.mutation, verdict: s.verdict, caught: s.rustFindings.some(f => f.includes("rust-build-time-capabilities")) })),
  real: real.map(r => ({ update: r.update, level: r.level, crates: r.crates.map(c => `${c.name} ${c.to} ${c.status}: ${c.error || c.level}`) })),
};
fs.writeFileSync(path.join(OUT, "rust.json"), JSON.stringify({ summary, clean, standins, real }, null, 2));
console.log(JSON.stringify(summary, null, 2));
