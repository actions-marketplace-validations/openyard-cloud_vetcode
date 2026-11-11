// The guard: what an agent is about to install or run, checked before it happens.
//
// A package install runs code from the internet with the user's rights (install scripts,
// import-time code), and an agent decides to do it in a second: a name it remembered wrong,
// a name a web page suggested, a release published an hour ago. The guard reads the command,
// finds the packages it would fetch, and looks at what a model cannot know by itself:
//   - does the package exist, and is its name one letter from a popular one;
//   - is there a malware advisory for it (OSV);
//   - how the release came to exist: hours old, provenance gone, a new install script;
//   - what the code does, by downloading the archive and reading it. Nothing is installed or run.
// The answer is allow, ask (a person should decide) or deny, with the reason in one line each.
//
// Everything that touches the network or the disk is passed in, so the logic is tested offline.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { analyzeHistory } from "./npmhistory.mjs";
import { lookalike } from "./supply.mjs";
import { POPULAR_SCOPES, KNOWN_NPM, KNOWN_PYPI, TARGET_NPM, TARGET_PYPI } from "./popular.mjs";

const HOUR = 3600000;
const RANK = { allow: 0, ask: 1, deny: 2 };
const VERDICT_CATS = new Set(["malware", "supply-chain", "agent"]);
// Installers the big toolchains publish; piping them to a shell is how they are meant to be used.
const INSTALLER = /^https:\/\/(?:(?:deb|rpm)\.nodesource\.com|get\.docker\.com|sh\.rustup\.rs|install\.python-poetry\.org|bun\.sh\/install|get\.pnpm\.io|astral\.sh\/|deno\.land\/install|get\.helm\.sh|raw\.githubusercontent\.com\/(?:nvm-sh\/nvm|Homebrew\/install)\/|claude\.ai\/install)/i;

// ---- reading the command -------------------------------------------------------------------

/** Splits a shell line into simple commands, each a list of words. Quotes are respected; no expansion. */
export function splitCommands(line) {
  const cmds = [[]];
  let word = "", quote = null, has = false;
  const push = () => { if (has) cmds.at(-1).push(word); word = ""; has = false; };
  const next = sep => { push(); cmds.at(-1).sep = sep; cmds.push([]); };
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) { if (c === quote) quote = null; else if (c === "\\" && quote === '"' && i + 1 < line.length) word += line[++i]; else word += c; continue; }
    if (c === "'" || c === '"') { quote = c; has = true; }
    else if (c === "\\" && i + 1 < line.length) { word += line[++i]; has = true; }
    else if (c === "\n" || c === ";") next(";");
    else if (c === "&" && line[i + 1] === "&") { next("&&"); i++; }
    else if (c === "|" && line[i + 1] === "|") { next("||"); i++; }
    else if (c === "|") next("|");
    else if (c === "&") next("&");
    else if (/\s/.test(c)) push();
    else { word += c; has = true; }
  }
  push();
  return cmds.filter(c => c.length);
}

const WRAPPERS = new Set(["sudo", "time", "command", "exec", "nohup", "env", "doas"]);
function strip(words) {
  let w = words.slice();
  while (w.length && (/^[A-Za-z_]\w*=/.test(w[0]) || WRAPPERS.has(w[0]) || (w[0].startsWith("-") && w.length > 1 && WRAPPERS.has(words[0])))) w = w.slice(1);
  return w;
}
const base = w => (w || "").replace(/^.*\//, "");

// Flags that take a value, per tool, so the value is not read as a package name.
const VALUE_FLAGS = {
  npm: /^(--registry|--prefix|-w|--workspace|--cache|--userconfig|--tag|--otp|-C|--omit|--include|--loglevel)$/,
  pip: /^(-r|--requirement|-c|--constraint|-i|--index-url|--extra-index-url|-f|--find-links|-t|--target|--prefix|--root|--python|--platform|--python-version|--implementation|--abi|--cache-dir|--src|--upgrade-strategy|--progress-bar|--config-settings|-C|--trusted-host|--proxy|--only-binary|--no-binary|--group|--extra|--with|--index|--default-index|-p)$/,
};

function npmSpec(spec) {
  if (/^(?:\.{0,2}\/|~\/|file:)|\.(?:tgz|tar\.gz)$/.test(spec) && !/^https?:/.test(spec)) return null; // a local folder or archive
  if (/^(?:https?:|git\+|git:|ssh:|github:|gitlab:|bitbucket:)|^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec)) return { eco: "npm", remote: spec };
  const alias = /^[^@]+@npm:(.+)$/.exec(spec) || /^@[^@]+@npm:(.+)$/.exec(spec);
  if (alias) spec = alias[1];
  const m = /^(@[\w.~-]+\/[\w.~-]+|[\w.~-]+)(?:@(.+))?$/.exec(spec);
  return m ? { eco: "npm", name: m[1].toLowerCase(), want: m[2] || null } : null;
}
function pipSpec(spec) {
  if (/^(?:\.{0,2}\/|~\/|\.$)|\.(?:whl|tar\.gz|zip)$/.test(spec) && !/^https?:/.test(spec)) return null;
  if (/^(?:https?:|git\+|hg\+|svn\+|bzr\+)|@\s*(?:https?:|git\+)/.test(spec)) return { eco: "pypi", remote: spec };
  const m = /^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(?:(==|===)\s*([\w.!+*-]+))?/.exec(spec);
  return m ? { eco: "pypi", name: m[1].toLowerCase().replace(/[-_.]+/g, "-"), want: m[3] || null } : null;
}

/** What a shell line would fetch and run: registry packages, other sources, and downloads piped to a shell. */
export function parseInstalls(line, { cwd = process.cwd(), exists = fs.existsSync } = {}) {
  const out = [], cmds = splitCommands(line);
  const add = (spec, via, parse) => { const p = parse(spec); if (p) out.push({ ...p, via }); };
  const args = (w, eco) => { const a = []; for (let i = 0; i < w.length; i++) { if (VALUE_FLAGS[eco].test(w[i])) { a.push({ flag: w[i], value: w[++i] }); continue; } if (w[i].startsWith("-")) { a.push({ flag: w[i].split("=")[0], value: w[i].includes("=") ? w[i].slice(w[i].indexOf("=") + 1) : null }); continue; } a.push({ word: w[i] }); } return a; };
  cmds.forEach((raw, i) => {
    const w = strip(raw), bin = base(w[0]);
    // curl … | sh
    if (raw.sep === "|" && /^(curl|wget)$/.test(bin) && /^(?:ba|z|da|k)?sh$/.test(base(strip(cmds[i + 1] || [])[0]))) {
      const url = w.find(x => /^https?:\/\//.test(x));
      if (!url || !INSTALLER.test(url)) out.push({ pipe: url || "a download", via: `${bin} | ${base(strip(cmds[i + 1])[0])}` });
      return;
    }
    if (/^(npm|pnpm|yarn|bun)$/.test(bin)) {
      const rest = w.slice(1), sub = rest.find(x => !x.startsWith("-")), after = rest.slice(rest.indexOf(sub) + 1);
      const global = sub === "global" && bin === "yarn";
      const verb = global ? after.find(x => !x.startsWith("-")) : sub, list = global ? after.slice(after.indexOf(verb) + 1) : after;
      if ((bin === "npm" && /^(i|in|ins|inst|insta|instal|install|isnt|isnta|isntal|isntall|add)$/.test(verb)) || (bin !== "npm" && verb === "add") || (bin === "bun" && /^(i|install)$/.test(verb) && list.some(x => !x.startsWith("-"))))
        for (const a of args(list, "npm")) if (a.word) add(a.word, `${bin} ${verb}`, npmSpec);
      if ((bin === "npm" && /^(exec|x)$/.test(verb)) || (/^(pnpm|yarn)$/.test(bin) && verb === "dlx") || (bin === "bun" && verb === "x")) runner(list, `${bin} ${verb}`);
      return;
    }
    if (/^(npx|bunx|pnpx)$/.test(bin)) return runner(w.slice(1), bin);
    if (/^pip[\d.]*$/.test(bin) && w[1] === "install") return pip(w.slice(2), "pip install");
    if (/^python[\d.]*$/.test(bin) && w[1] === "-m" && w[2] === "pip" && w[3] === "install") return pip(w.slice(4), "pip install");
    if (bin === "uv") {
      if (w[1] === "pip" && w[2] === "install") return pip(w.slice(3), "uv pip install");
      if (w[1] === "add") return pip(w.slice(2), "uv add");
      if (w[1] === "tool" && /^(run|install)$/.test(w[2])) return pyRunner(w.slice(3), `uv tool ${w[2]}`);
    }
    if (bin === "uvx") return pyRunner(w.slice(1), "uvx");
    if (bin === "pipx" && /^(install|run)$/.test(w[1])) return pyRunner(w.slice(2), `pipx ${w[1]}`);
    if (bin === "poetry" && w[1] === "add") return pip(w.slice(2), "poetry add");
  });
  return out;

  // npx-style: the first plain word is the package, unless -p / --package names it.
  function runner(list, via) {
    const named = [];
    for (let i = 0; i < list.length; i++) {
      if (/^(-p|--package)$/.test(list[i])) { named.push(list[++i]); continue; }
      if (list[i].startsWith("--package=")) { named.push(list[i].slice(10)); continue; }
      if (/^(-c|--call)$/.test(list[i])) { i++; continue; }
      if (list[i].startsWith("-")) continue;
      if (!named.length) named.push(list[i]);
      break;
    }
    for (const spec of named.filter(Boolean)) {
      // A tool already installed in the project runs from node_modules; nothing is fetched.
      const bare = spec.replace(/@[^/]*$/, "");
      if (!spec.includes("@", 1) && exists(path.join(cwd, "node_modules", ".bin", bare))) continue;
      add(spec, via, npmSpec);
    }
  }
  function pip(list, via) {
    for (const a of args(list, "pip")) {
      if (a.word) add(a.word, via, pipSpec);
      else if (/^(-i|--index-url|--extra-index-url|--index|--default-index)$/.test(a.flag) && a.value && !/^https:\/\/(?:pypi\.org|files\.pythonhosted\.org|download\.pytorch\.org)\//.test(a.value)) out.push({ eco: "pypi", index: a.value, via });
    }
  }
  function pyRunner(list, via) {
    const from = list.findIndex(x => /^(--from|--with|--spec)$/.test(x));
    if (from >= 0 && list[from + 1]) return add(list[from + 1], via, pipSpec);
    const first = list.find(x => !x.startsWith("-"));
    if (first) add(first, via, pipSpec);
  }
}

// ---- looking a package up -------------------------------------------------------------------

const json = async (fetchFn, url, init) => { const r = await fetchFn(url, { headers: { "user-agent": "vetcode-guard", accept: "application/json" }, signal: AbortSignal.timeout(8000), ...init }); return { status: r.status, body: r.ok ? await r.json() : null }; };

async function malwareAdvisories(fetchFn, ecosystem, name, version) {
  try {
    const r = await json(fetchFn, "https://api.osv.dev/v1/query", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(version ? { package: { name, ecosystem }, version } : { package: { name, ecosystem } }) });
    return (r.body?.vulns || []).filter(v => /^MAL-/.test(v.id) || (v.aliases || []).some(a => /^MAL-/.test(a))).map(v => v.id);
  } catch { return null; } // unknown, not "none"
}

// Version numbers compared part by part; pre-releases (1.0.0-rc.1, 2.0b1, .dev3) are left out by the callers.
const parts = v => String(v).split(/[.+]/).map(x => parseInt(x, 10) || 0);
const newer = (a, b) => { const x = parts(a), y = parts(b); for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); return false; };
const PRE = /-|[a-z]/i;
/** The newest release older than the waiting period, below the one asked for: what to install instead of a brand-new release. */
export function settledVersion(times, fresh, now, minAgeHours) {
  let best = null;
  for (const [v, t] of Object.entries(times)) {
    const at = Date.parse(t);
    if (!Number.isFinite(at) || PRE.test(v) || v === fresh || now - at < minAgeHours * HOUR || newer(v, fresh)) continue;
    if (!best || newer(v, best.version)) best = { version: v, days: Math.floor((now - at) / (24 * HOUR)) };
  }
  return best;
}

// The newest version that is not a pre-release, or what the tag or exact version names.
function npmVersion(doc, want) {
  if (want && doc.versions?.[want]) return want;
  if (want && doc["dist-tags"]?.[want]) return doc["dist-tags"][want];
  return doc["dist-tags"]?.latest || Object.keys(doc.versions || {}).at(-1);
}

/**
 * One package, checked. Returns { decision, reasons[], notes[], name, version }.
 * deps: { fetch, now, scan(eco, archiveUrl, size) -> findings | null, minAgeHours }
 */
export async function checkPackage(pkg, deps = {}) {
  const fetchFn = deps.fetch || fetch, now = deps.now ?? Date.now(), minAge = deps.minAgeHours ?? 72;
  const reasons = [], notes = [];
  let decision = "allow", version = pkg.want;
  const raise = (d, why) => { if (RANK[d] > RANK[decision]) decision = d; reasons.push(why); };
  const done = () => ({ name: pkg.name, eco: pkg.eco, version, decision, reasons, notes });
  const npm = pkg.eco === "npm";
  const known = (npm ? KNOWN_NPM : KNOWN_PYPI).has(pkg.name);
  // A package that comes from a private registry is not looked up anywhere else: its name is not ours to send.
  if (deps.isPrivate?.(pkg)) { notes.push("comes from a private registry: not checked"); return done(); }

  let doc, archive, size, published, times = {};
  try {
    const r = npm ? await json(fetchFn, `https://registry.npmjs.org/${pkg.name.replace("/", "%2F")}`)
      : await json(fetchFn, `https://pypi.org/pypi/${pkg.name}${pkg.want ? "/" + pkg.want : ""}/json`);
    if (r.status === 404) { raise("deny", `${pkg.name} does not exist on ${npm ? "npm" : "PyPI"}${pkg.want ? " at that version" : ""}. Check the name: a made-up name is one an attacker can register.`); return done(); }
    doc = r.body;
  } catch { /* registry unreachable: decide on what we have */ }

  if (doc && npm) {
    version = npmVersion(doc, pkg.want);
    const v = doc.versions?.[version];
    if (!v) { raise("deny", `${pkg.name}@${pkg.want} is not a published version.`); return done(); }
    archive = v.dist?.tarball; size = v.dist?.unpackedSize; published = Date.parse(doc.time?.[version] || "");
    times = Object.fromEntries(Object.keys(doc.versions).map(x => [x, doc.time?.[x]]));
    for (const f of analyzeHistory(doc, version, { now })) {
      if (f.rule === "npm-fresh-release") continue; // handled below with the configured age
      // Lesser oddities (a new publisher, a long silence) are worth a line only for a name with no reputation.
      if (f.severity === "high") raise("ask", `${f.title}.`); else if (!known && f.severity === "medium") notes.push(f.title);
    }
    if (["preinstall", "install", "postinstall"].some(h => v.scripts?.[h]) && !known) notes.push(`runs an install script: ${["preinstall", "install", "postinstall"].filter(h => v.scripts?.[h]).map(h => v.scripts[h]).join("; ").slice(0, 120)}`);
  } else if (doc) {
    version = doc.info?.version;
    const files = doc.urls || [], sdist = files.find(f => f.packagetype === "sdist"), pick = sdist || files.find(f => /\.whl$/.test(f.filename || ""));
    archive = pick?.url; size = pick?.size; published = Math.min(...files.map(f => Date.parse(f.upload_time_iso_8601 || f.upload_time || "")).filter(Number.isFinite));
    times = Object.fromEntries(Object.entries(doc.releases || {}).map(([x, fl]) => [x, fl?.[0]?.upload_time_iso_8601 || fl?.[0]?.upload_time]));
    if (doc.info?.yanked) raise("ask", `${pkg.name} ${version} was yanked by its maintainers${doc.info.yanked_reason ? `: ${doc.info.yanked_reason}` : ""}.`);
  }

  const mal = await malwareAdvisories(fetchFn, npm ? "npm" : "PyPI", pkg.name, version);
  if (mal?.length) { raise("deny", `${pkg.name}${version ? "@" + version : ""} is reported as malware (${mal.slice(0, 3).join(", ")}).`); return done(); }
  if (mal === null) notes.push("the advisory database could not be reached");

  const like = known ? null : lookalike(pkg.name, npm ? TARGET_NPM : TARGET_PYPI, POPULAR_SCOPES, npm ? KNOWN_NPM : KNOWN_PYPI);
  if (like) raise("ask", `${pkg.name} looks like the popular package ${like}. If ${like} was meant, install that instead.`);

  if (Number.isFinite(published) && now - published < minAge * HOUR) {
    // Say what to install instead, so an agent can carry on without the new release.
    const old = settledVersion(times, version, now, minAge), at = npm ? "@" : "==";
    raise("ask", `${pkg.name}@${version} was published ${Math.max(1, Math.round((now - published) / HOUR))} hours ago, and most malicious releases are removed within a few days. ${old ? `The newest settled version is ${old.version} (${old.days} days old): install ${pkg.name}${at}${old.version} instead, or let the user accept the new release.` : "There is no older release to fall back on: let the user decide."}`);
  }

  // Read the code when the name carries no reputation or something above already looks off.
  if (archive && deps.scan && (!known || decision !== "allow") && !(size > 40 << 20)) {
    let findings = null;
    try { findings = await deps.scan(pkg.eco, archive, size); } catch { /* could not read it */ }
    if (findings === null) notes.push("the package archive could not be read");
    else {
      // The scanner also notices a look-alike name; that was said once above.
      const hits = findings.filter(f => VERDICT_CATS.has(f.category) && f.confidence !== "low" && (f.severity === "critical" || f.severity === "high") && !(like && /typosquat/.test(f.rule)));
      const worst = hits.some(f => f.severity === "critical") ? "critical" : hits.length ? "high" : null;
      const say = hits.slice(0, 3).map(f => `${f.title} (${f.file}${f.line ? ":" + f.line : ""})`).join("; ");
      if (worst === "critical") raise("deny", `The code of ${pkg.name}@${version} looks malicious: ${say}.`);
      else if (worst === "high") raise("ask", `The code of ${pkg.name}@${version} has signs of malware that need a look: ${say}.`);
      else notes.push(`code read (${findings.stats?.files ?? "?"} files), nothing serious found`);
    }
  }
  return done();
}

// ---- the whole command ----------------------------------------------------------------------

/** Checks every package a shell line would fetch. Returns { decision, message, results }. */
export async function guard(line, deps = {}) {
  const items = parseInstalls(line, deps), results = [];
  let decision = "allow";
  const raise = d => { if (RANK[d] > RANK[decision]) decision = d; };
  const seen = new Set(), pending = [];
  for (const it of items) {
    if (it.pipe) { results.push({ decision: "ask", reasons: [`This pipes ${it.pipe} straight into a shell: whatever that address serves runs with your rights. Download it, read it, then run it.`] }); raise("ask"); continue; }
    if (it.index) { results.push({ decision: "ask", reasons: [`This installs from another package index (${it.index}). A package there can shadow one of the same name on PyPI.`] }); raise("ask"); continue; }
    if (it.remote) { results.push({ decision: "ask", reasons: [`${it.remote} is fetched from a repository or URL, not from the registry, so it cannot be checked before it runs. Clone it and scan it with vetcode first.`] }); raise("ask"); continue; }
    const key = `${it.eco}:${it.name}@${it.want || ""}`;
    if (seen.has(key) || seen.size >= (deps.limit ?? 12)) continue;
    seen.add(key);
    pending.push(checkPackage(it, deps));
  }
  for (const r of await Promise.all(pending)) { results.push(r); raise(r.decision); }
  const strict = deps.mode === "strict" && decision === "ask";
  if (strict) decision = "deny";
  const lines = results.filter(r => r.decision !== "allow").flatMap(r => r.reasons);
  const notes = results.filter(r => r.decision === "allow" && r.notes?.length && !(r.notes.length === 1 && /nothing serious/.test(r.notes[0]))).map(r => `${r.name}: ${r.notes.join("; ")}`);
  return { decision, message: lines.length ? `vetcode: ${lines.join(" ")}` : "", notes, results, checked: results.filter(r => r.name).length };
}

// ---- the real scan: download the archive, unpack it, read it, delete it -----------------------

/** Used by the hook. Nothing from the archive is executed; it is unpacked into an empty folder and read. */
export async function scanArchive(eco, url, _size, { fetch: fetchFn = fetch, vet } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vetcode-guard-"));
  try {
    const r = await fetchFn(url, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) return null;
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > 40 << 20) return null;
    const file = path.join(dir, /\.(whl|zip)$/.test(url) ? "pkg.zip" : "pkg.tgz"), into = path.join(dir, "src");
    fs.writeFileSync(file, buf); fs.mkdirSync(into);
    const un = file.endsWith(".zip") ? spawnSync("unzip", ["-qq", "-o", file, "-d", into]) : spawnSync("tar", ["-xzf", file, "-C", into, "--no-same-owner"]);
    if (un.status !== 0 && !fs.readdirSync(into).length) return null;
    const top = fs.readdirSync(into), root = top.length === 1 && fs.statSync(path.join(into, top[0])).isDirectory() ? path.join(into, top[0]) : into;
    const res = await vet(root, { tools: false, noIgnore: true, log: () => {} });
    return Object.assign(res.findings, { stats: res.stats });
  } catch { return null; }
  finally { spawnSync("chmod", ["-R", "u+rwX", dir]); fs.rmSync(dir, { recursive: true, force: true }); }
}

/**
 * Which packages come from a private registry, from the project's and the user's npm and pip
 * settings. Only the registry lines are read; tokens in the same files are never touched.
 */
export function privateRegistries({ cwd = process.cwd(), home = os.homedir(), env = process.env, read = f => { try { return fs.readFileSync(f, "utf8"); } catch { return ""; } } } = {}) {
  const PUBLIC_NPM = /^https?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/?$/, PUBLIC_PY = /^https:\/\/(?:pypi\.org|files\.pythonhosted\.org)\//;
  const scopes = new Set(); let allNpm = false, allPy = false;
  for (const f of [path.join(cwd, ".npmrc"), path.join(home, ".npmrc")]) for (const line of read(f).split(/\r?\n/)) {
    const m = /^\s*(?:(@[\w.-]+):)?registry\s*=\s*(\S+)/.exec(line);
    if (!m || PUBLIC_NPM.test(m[2])) continue;
    if (m[1]) scopes.add(m[1].toLowerCase()); else allNpm = true;
  }
  if (env.npm_config_registry && !PUBLIC_NPM.test(env.npm_config_registry)) allNpm = true;
  for (const k of ["PIP_INDEX_URL", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "PIP_EXTRA_INDEX_URL", "UV_EXTRA_INDEX_URL"]) if (env[k] && !PUBLIC_PY.test(env[k])) allPy = true;
  for (const f of [path.join(cwd, "pip.conf"), path.join(home, ".pip", "pip.conf"), path.join(home, ".config", "pip", "pip.conf")]) if (/^\s*(?:extra-)?index-url\s*=\s*(?!https:\/\/pypi\.org\/)\S+/m.test(read(f))) allPy = true;
  return pkg => pkg.eco === "npm" ? allNpm || scopes.has((pkg.name.match(/^(@[^/]+)\//) || [])[1]) : allPy;
}

