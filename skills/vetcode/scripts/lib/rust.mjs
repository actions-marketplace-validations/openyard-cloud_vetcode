// Rust code that runs while a project is built: build scripts (build.rs) run on every `cargo build`
// and `cargo check`, and procedural macros run inside the compiler and inside rust-analyzer as soon
// as a project is opened. They play the part npm install scripts play, so they get the same three
// things: what they can do (a label per crate, with build time apart), rules for the combinations
// malware uses, and a comparison of two Cargo.lock files that names what an update brought in.
//
// Legitimate build scripts are busy: cc and cmake start compilers, bindgen and prost-build start
// clang and protoc, vergen reads git, built reads environment variables, -sys crates may download
// a prebuilt library. So starting a program or downloading is "worth a look"; the warning is for
// network access together with secrets, a shell, decoding, host details or writes to the home folder.
import fs from "node:fs";
import path from "node:path";
import { finding, lineOf } from "./engine.mjs";

// What Rust code can do, in the same words as the npm and PyPI label.
export const RUST_CAPS = {
  "reads environment or credential files": /\benv::vars(?:_os)?\s*\(|\.ssh\b|\.aws\b|\.cargo[\\/]credentials|credentials\.toml|\.git-credentials|\.npmrc|\.docker[\\/]config|\.kube[\\/]config|\bid_rsa\b|\bid_ed25519\b|Login Data|\bwallet\b|keychain|env::var(?:_os)?\(\s*"[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z_]*"/,
  "uses the network": /\bstd::net::|\bTcpStream::connect|\bUdpSocket::bind|\b(?:reqwest|ureq|attohttpc|minreq|isahc|surf|hyper|curl|http_req)::|Command::new\(\s*"(?:curl|wget|powershell|pwsh|nc|ncat)"/,
  "runs other programs": /\bCommand::new\s*\(/,
  "collects user and host details": /\b(?:whoami|hostname|gethostname|sysinfo|machine_uid|mac_address)::|\bgethostname\s*\(|\bget_current_username\b|Command::new\(\s*"(?:whoami|hostname|uname|id)"|Command::new\(\s*"git"\s*\)[\s\S]{0,160}?\.args?\(\s*\[?\s*"(?:config|remote|log|credential)"/,
  "writes into home or startup folders": /(?:fs::(?:write|copy|create_dir_all|rename)|File::create|OpenOptions::new\(\))[^;\n]{0,200}?(?:home_dir\s*\(|"(?:HOME|USERPROFILE|APPDATA)"|\.bashrc|\.zshrc|\.profile|\.ssh|\.cargo[\\/]bin|LaunchAgents|Startup|autostart)/,
  "decodes or builds code at runtime": /\bbase64::(?:decode|engine|prelude|\{[^}]*\b(?:engine|Engine|decode)\b)|\b(?:STANDARD|URL_SAFE)(?:_NO_PAD)?\.decode\s*\(|\.decode\(\s*(?:&?\s*)?"[A-Za-z0-9+/=]{40,}|\bfrom_base64\b|\blibloading::|\bLibrary::new\s*\(|include_bytes!\s*\(\s*"[^"]*\.(?:bin|dat|enc|b64|payload|so|dll|dylib|exe)"|\bmemfd_create\b|\bmmap\b[\s\S]{0,80}PROT_EXEC/,
};
export const rustCapabilitiesOf = text => Object.entries(RUST_CAPS).filter(([, re]) => re.test(text)).map(([name]) => name);

// String building that hides a name from a reader and from patterns: concat!("cu", "rl"),
// character codes through char::from or String::from_utf8, and reversed literals. Rewritten to the
// plain literal, keeping the line count so evidence still points at the right line.
const keepLines = (orig, rep) => rep + "\n".repeat((orig.match(/\n/g) || []).length);
const fromCodes = list => { const n = list.split(",").map(x => parseInt(x.trim().replace(/_?u8$/, ""), x.trim().startsWith("0x") ? 16 : 10)); return n.length >= 2 && n.every(c => c >= 32 && c < 127) ? String.fromCharCode(...n) : null; };
export function rustExpanded(text) {
  if (!/concat!|char::from|from_utf8|as char|\.rev\(\)|&\s*"/.test(text)) return text;
  return text
    .replace(/concat!\s*\(\s*((?:"[^"\\\n]*"\s*,?\s*)+)\)/g, (m, parts) => keepLines(m, JSON.stringify([...parts.matchAll(/"([^"\\\n]*)"/g)].map(x => x[1]).join(""))))
    .replace(/(?:vec!|&?)\[\s*((?:(?:0x[0-9a-fA-F]+|\d+)(?:_?u8)?\s*,\s*){1,200}(?:0x[0-9a-fA-F]+|\d+)(?:_?u8)?)\s*,?\s*\](?=[\s\S]{0,120}?(?:char::from|as char|from_utf8))/g, (m, list) => { const str = fromCodes(list); return str ? keepLines(m, JSON.stringify(str)) : m; })
    .replace(/(from_utf8(?:_lossy)?\s*\(\s*)(?:vec!|&)?\[\s*((?:(?:0x[0-9a-fA-F]+|\d+)(?:_?u8)?\s*,\s*){1,200}(?:0x[0-9a-fA-F]+|\d+)(?:_?u8)?)\s*,?\s*\]/g, (m, pre, list) => { const str = fromCodes(list); return str ? keepLines(m, pre + JSON.stringify(str)) : m; })
    .replace(/"([^"\\\n]{2,200})"\s*\.chars\(\)\s*\.rev\(\)\s*\.collect::<String>\(\)/g, (m, str) => JSON.stringify([...str].reverse().join("")))
    // What is left around a literal once it is plain: String::from_utf8("x").unwrap(), &"x".
    .replace(/(?:String::)?from_utf8(?:_lossy)?\(\s*("[^"\\\n]*")\s*\)(?:\.unwrap\(\)|\.expect\([^)]*\)|\.into_owned\(\))?/g, "$1")
    .replace(/&\s*("[^"\\\n]*")/g, "$1");
}

// What turns a downloading build script into a dropper or an exfiltrator. Each was in a real attack:
// proc-macro1 (arrayref 0.3.10) rebuilt its server address from base64, fetched with certificate
// checks off, wrote /tmp/rust-setup, made it executable and started it (wscript and PowerShell on
// Windows); onering 1.4.1 read `git log` and `git diff HEAD^ HEAD` and posted them with curl.
const EXTRA = {
  // Program names in any case; the shell flags exactly (tar's -C is not sh's -c).
  "starts a shell": /Command::new\(\s*"(?:[Ss][Hh]|bash|zsh|dash|[Cc][Mm][Dd](?:\.exe)?|[Pp]ower[Ss]hell(?:\.exe)?|pwsh|osascript|[Ww][Ss]cript(?:\.exe)?|[Cc][Ss]cript|mshta|rundll32|regsvr32)"|\.args?\(\s*\[?\s*"(?:\/C|\/c|-EncodedCommand|-enc|-ExecutionPolicy)"/,
  "starts a program it wrote": /from_mode\(\s*0o?7[0-7]{2}\s*\)|\bstd::mem::forget\(\s*\w*child|Command::new\(\s*&?\s*(?:\w+\.)?(?:tmp|temp|dest|target|out|exe|bin|payload|setup|path)\w*\s*\)|temp_dir\(\)[\s\S]{0,300}?Command::new/i,
  "turns off certificate checks": /\bServerCertVerifier\b|\.dangerous\(\)|danger_accept_invalid_certs\s*\(\s*true|\bAcceptAll\w*/,
  "reads the project's git history": /"(?:diff|log|show)"\s*,\s*"(?:-n|-1|-p|HEAD|--format|--pretty|--patch)|"config"\s*,\s*"(?:--get|user\.)|"remote"\s*,\s*"get-url"|"credential"\s*,\s*"fill"/,
};
const extrasOf = text => Object.entries(EXTRA).filter(([, re]) => re.test(text)).map(([name, re]) => ({ name, re }));

const strip = s => s.replace(/#.*$/gm, "");
/** The parts of a Cargo.toml that say what runs at build time. Not a TOML parser: enough for these keys. */
export function cargoManifest(text) {
  const t = strip(text), section = name => { const m = new RegExp(`^\\[${name}\\]\\s*$([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`, "m").exec(t); return m ? m[1] : ""; };
  const str = (sec, key) => new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, "m").exec(sec)?.[1];
  const pkg = section("package");
  const buildRaw = /^\s*build\s*=\s*(false|"[^"]*")/m.exec(pkg)?.[1];
  const lib = section("lib");
  const deps = [];
  for (const m of t.matchAll(/^\[(?:target\.[^\]]+\.)?build-dependencies\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/gm))
    for (const d of m[1].matchAll(/^\s*([A-Za-z0-9_-]+)\s*=/gm)) deps.push(d[1]);
  for (const m of t.matchAll(/^\[(?:target\.[^\]]+\.)?build-dependencies\.([A-Za-z0-9_-]+)\]/gm)) deps.push(m[1]);
  return {
    name: str(pkg, "name"), version: str(pkg, "version"), description: str(pkg, "description") || "",
    build: buildRaw === "false" ? false : buildRaw ? buildRaw.slice(1, -1) : null,
    procMacro: /^\s*proc[-_]macro\s*=\s*true\b/m.test(lib),
    buildDependencies: [...new Set(deps)],
    workspaceOnly: !pkg && /^\[workspace\]/m.test(t),
  };
}

const read = abs => { try { return fs.statSync(abs).size < 4e6 ? fs.readFileSync(abs, "utf8") : ""; } catch { return ""; } };

// A build script and the modules it declares next to it (`mod x;` → x.rs or x/mod.rs), two levels deep.
function withModules(abs, depth = 2, seen = new Set()) {
  if (seen.has(abs) || seen.size > 20) return [];
  seen.add(abs);
  const text = read(abs);
  if (!text) return [];
  const out = [{ abs, text }];
  if (depth) for (const m of text.matchAll(/^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;/gm)) {
    const base = path.basename(abs) === "mod.rs" || path.basename(abs) === "main.rs" || path.basename(abs) === "build.rs" || path.basename(abs) === "lib.rs" ? path.dirname(abs) : path.join(path.dirname(abs), path.basename(abs, ".rs"));
    for (const cand of [path.join(base, m[1] + ".rs"), path.join(base, m[1], "mod.rs")]) if (fs.existsSync(cand)) { out.push(...withModules(cand, depth - 1, seen)); break; }
  }
  return out;
}

// A build script that includes a base64 file and decodes it is reading code or addresses it does
// not want seen: the decoded text is read with the script (at its end, so line numbers hold).
function includedPayloads(abs, text) {
  if (!/\bdecode\b|from_base64|base64::/.test(text)) return "";
  let out = "";
  for (const m of text.matchAll(/include_(?:str|bytes)!\s*\(\s*"([^"]+)"\s*\)/g)) {
    const raw = read(path.resolve(path.dirname(abs), m[1])).trim();
    if (raw.length < 16 || raw.length > 1e6 || !/^[A-Za-z0-9+/=\s_-]+$/.test(raw)) continue;
    const dec = Buffer.from(raw.replace(/\s+/g, ""), "base64").toString("utf8");
    if (!/^[\x09\x0a\x0d\x20-\x7e]*$/.test(dec)) continue;
    const lines = dec.split("\n").map(l => l.replace(/["\\]/g, ""));
    out += "\n" + lines.map(l => `"${l}"`).join("\n");
    // A program name kept in the encoded file, started through a variable: Command::new(&S[1]).
    if (/Command::new\(\s*&?\s*[A-Za-z_]/.test(text)) out += "\n" + lines.filter(l => /^(?:curl|wget|sh|bash|powershell|pwsh|cmd)$/.test(l.trim())).map(l => `Command::new("${l.trim()}")`).join("\n");
  }
  return out;
}

/**
 * Every crate in a folder (each Cargo.toml with a [package]), with what its code can do and,
 * apart, what its build-time code can do: the build script and, for a proc-macro crate, all its source.
 */
export function crateProfiles(root, files) {
  const tomls = files.filter(f => path.basename(f.rel) === "Cargo.toml");
  const crates = [];
  for (const t of tomls) {
    const m = cargoManifest(t.text);
    if (!m.name) continue;
    const dir = path.dirname(t.rel) === "." ? "" : path.dirname(t.rel);
    crates.push({ ...m, dir, file: t.rel });
  }
  crates.sort((a, b) => b.dir.length - a.dir.length);
  const own = rel => crates.find(c => !c.dir || rel.startsWith(c.dir + "/"));
  for (const c of crates) { c.capabilities = {}; c.buildTime = {}; c.buildFiles = []; c.codeFiles = 0; }
  for (const f of files) {
    if (!f.rel.endsWith(".rs")) continue;
    const c = own(f.rel);
    if (!c) continue;
    c.codeFiles++;
    for (const cap of rustCapabilitiesOf(rustExpanded(f.text))) (c.capabilities[cap] ||= []).push(f.rel);
  }
  for (const c of crates) {
    const at = rel => path.join(root, c.dir, rel), relOf = abs => path.relative(root, abs).split(path.sep).join("/");
    const script = c.build === false ? null : c.build || (fs.existsSync(at("build.rs")) ? "build.rs" : null);
    c.buildScript = script ? path.posix.join(c.dir, script) : null;
    const units = [];
    if (script && fs.existsSync(at(script))) units.push(...withModules(at(script)));
    if (c.procMacro) for (const f of files) if (f.rel.endsWith(".rs") && own(f.rel) === c && /(^|\/)src\//.test(f.rel.slice(c.dir.length))) units.push({ abs: f.abs || path.join(root, f.rel), text: f.text });
    const seen = new Set();
    for (const u of units) {
      const rel = relOf(u.abs);
      if (seen.has(rel)) continue;
      const text = rustExpanded(u.text) + includedPayloads(u.abs, u.text);
      seen.add(rel); c.buildFiles.push({ rel, text });
      for (const cap of rustCapabilitiesOf(text)) (c.buildTime[cap] ||= []).push(rel);
    }
  }
  return crates;
}

const RULE = { category: "supply-chain", confidence: "medium" };
const RISKY = ["decodes or builds code at runtime", "collects user and host details", "writes into home or startup folders"];
// Reading one named token (GITHUB_TOKEN to authenticate a download) is in the label; credential
// files and a dump of every variable are what an exfiltrator reads.
const STEALS = /(?<!envs\(\s*(?:std::)?)\benv::vars(?:_os)?\s*\(|\.ssh\b|\.aws\b|\.cargo[\\/]credentials|credentials\.toml|\.git-credentials|\.npmrc|\.docker[\\/]config|\.kube[\\/]config|\bid_rsa\b|\bid_ed25519\b|Login Data|\bwallet\b|keychain/;

/**
 * Rules for build-time Rust code, per crate. Returns the files that run at build time, which the
 * verdict treats like files an install script starts.
 */
export function scanBuildTime(crates, out) {
  const buildFiles = new Set();
  for (const c of crates) {
    if (!c.buildFiles.length) continue;
    for (const f of c.buildFiles) buildFiles.add(f.rel);
    const text = c.buildFiles.map(f => f.text).join("\n");
    const caps = Object.keys(c.buildTime), net = caps.includes("uses the network");
    const extras = extrasOf(text), shell = extras.find(e => e.name === "starts a shell");
    const risky = [...(STEALS.test(text) ? ["reads credential files or every environment variable"] : []), ...RISKY.filter(x => caps.includes(x)), ...extras.filter(e => e !== shell).map(e => e.name)];
    const where = c.buildScript && c.buildFiles.some(f => f.rel === c.buildScript) ? c.buildScript : c.buildFiles[0].rel;
    const kind = c.procMacro && !c.buildScript ? "procedural macro" : c.procMacro ? "build script and procedural macro" : "build script";
    const ev = (re, label) => { for (const f of c.buildFiles) { const m = re.exec(f.text); if (m) return { file: f.rel, line: lineOf(f.text, m.index), evidence: `${label}: ${m[0].slice(0, 100)}` }; } return { file: where, line: 1, evidence: label }; };
    if (net && (risky.length || shell)) {
      const parts = [...risky, ...(shell ? ["starts a shell"] : [])];
      const at = ev(RUST_CAPS["uses the network"], `network + ${parts.join(" + ")}`);
      out.push(finding({ ...RULE, id: "rust-build-time-capabilities", severity: "critical", title: `Rust ${kind} of ${c.name} combines network access with ${parts.slice(0, 2).join(" and ")}`,
        why: `This code runs during \`cargo build\`, \`cargo check\` and in the editor, before any program exists. It uses the network and ${parts.join(", ")}. Build scripts compile and generate code; reaching the network together with these is how the arrayref/proc-macro1 and onering attacks worked.`,
        fix: "Do not build the project on a machine with credentials until this is explained. Pin the crate to its previous version in Cargo.lock and read the build script." }, at.file, at.line, at.evidence, { atInstall: true }));
    } else if (!net && shell && /\.ssh\b|\.aws\b|credentials|id_rsa|id_ed25519|wallet|Login Data/.test(text)) {
      const at = ev(shell.re, "secrets + starts a shell");
      out.push(finding({ ...RULE, id: "rust-build-time-secrets-shell", severity: "high", title: `Rust ${kind} of ${c.name} reads credential files and starts a shell`,
        why: "Build-time code has no reason to read SSH keys, cloud credentials or wallets, let alone hand them to a shell.",
        fix: "Do not build it. Read the build script; if it ran, rotate the credentials it could read." }, at.file, at.line, at.evidence, { atInstall: true }));
    } else if (net || shell) {
      // A download alone is how -sys crates fetch a prebuilt library: a place to look, not a verdict.
      const at = net ? ev(RUST_CAPS["uses the network"], "network") : ev(shell.re, "shell");
      out.push(finding({ ...RULE, id: "rust-build-time-download", severity: "medium", title: `Rust ${kind} of ${c.name} ${net ? "uses the network" : "starts a shell or downloader"} at build time`,
        why: "Some crates download a prebuilt library or tool while building. It is still code from the network entering the build, unpinned unless the script checks a hash.",
        fix: "Check where it downloads from and whether it verifies a checksum; prefer a feature that builds from source." }, at.file, at.line, at.evidence));
    }
  }
  return buildFiles;
}

/** [{ name, version, source, checksum }] from a Cargo.lock (v1 to v4). */
export function parseCargoLock(text) {
  const out = [];
  for (const block of String(text).split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const get = k => new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, "m").exec(block)?.[1];
    const name = get("name"), version = get("version");
    // dependencies = ["serde", "syn 2.0.1", "x 1.0 (registry+...)"]: the name is the first word.
    const deps = [.../^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(block)?.[1].matchAll(/"([^"\s]+)[^"]*"/g) || []].map(m => m[1]);
    if (name && version) out.push({ name, version, source: get("source") || null, checksum: get("checksum") || null, dependencies: deps });
  }
  return out;
}

const CRATES_IO = /^registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index$|^sparse\+https:\/\/index\.crates\.io\/$/;

/** What changed between two Cargo.lock files: crates added, removed and changed, from crates.io or elsewhere. */
export function lockChanges(oldText, newText) {
  const key = p => `${p.name}`;
  const before = new Map(), after = new Map();
  for (const p of parseCargoLock(oldText)) (before.get(key(p)) || before.set(key(p), []).get(key(p))).push(p);
  for (const p of parseCargoLock(newText)) (after.get(key(p)) || after.set(key(p), []).get(key(p))).push(p);
  const added = [], changed = [], removed = [];
  for (const [name, list] of after) {
    const old = before.get(name) || [];
    for (const p of list) {
      if (old.some(o => o.version === p.version)) continue;
      // A crate that had another version before is an update of it; a name never seen is new.
      const prev = old.filter(o => !list.some(n => n.version === o.version));
      if (prev.length) changed.push({ ...p, from: prev[prev.length - 1] }); else added.push(p);
    }
  }
  for (const [name, list] of before) if (!after.has(name)) removed.push(...list);
  // Who asked for each added crate: arrayref 0.3.10 is how proc-macro1 came in.
  const requiredBy = name => [...after.values()].flat().filter(p => p.dependencies.includes(name)).map(p => `${p.name} ${p.version}`);
  for (const p of added) p.requiredBy = requiredBy(p.name);
  return { added, changed, removed, fromCratesIo: p => !!p.source && CRATES_IO.test(p.source) };
}

/** A crate's .crate archive from crates.io, unpacked into a temporary folder. Nothing is built or run. */
export async function fetchCrate(name, version, { fetch: fetchFn = fetch, tmp } = {}) {
  const { spawnSync } = await import("node:child_process");
  const os = await import("node:os");
  const dir = fs.mkdtempSync(path.join(tmp || os.tmpdir(), "vetcode-crate-"));
  const r = await fetchFn(`https://static.crates.io/crates/${encodeURIComponent(name)}/${encodeURIComponent(name)}-${encodeURIComponent(version)}.crate`, { signal: AbortSignal.timeout(120000) }).catch(() => null);
  if (!r?.ok) { fs.rmSync(dir, { recursive: true, force: true }); return null; }
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > 40 << 20) { fs.rmSync(dir, { recursive: true, force: true }); return null; }
  const file = path.join(dir, "crate.tgz"), into = path.join(dir, "src");
  fs.writeFileSync(file, buf); fs.mkdirSync(into);
  const un = spawnSync("tar", ["-xzf", file, "-C", into, "--no-same-owner"]);
  const top = fs.existsSync(into) ? fs.readdirSync(into) : [];
  if (un.status !== 0 && !top.length) { fs.rmSync(dir, { recursive: true, force: true }); return null; }
  const root = top.length === 1 && fs.statSync(path.join(into, top[0])).isDirectory() ? path.join(into, top[0]) : into;
  return { root, cleanup: () => { spawnSync("chmod", ["-R", "u+rwX", dir]); fs.rmSync(dir, { recursive: true, force: true }); } };
}

const CAP_ORDER = ["uses the network", "starts a shell", "starts a program it wrote", "reads environment or credential files", "collects user and host details",
  "writes into home or startup folders", "decodes or builds code at runtime", "turns off certificate checks", "reads the project's git history", "runs other programs"];

/** A crate's build-time profile and its build-time findings, read from crates.io without building it. */
async function buildProfile(name, version, { fetch: fetchFn, vet }) {
  const c = await fetchCrate(name, version, { fetch: fetchFn });
  if (!c) return null;
  try {
    const r = await vet(c.root, { tools: false, noIgnore: true, places: false, log: () => {} });
    const p = r.profiles.find(x => x.kind === "crate" && x.name === name) || r.profiles.find(x => x.kind === "crate");
    const bt = p?.buildTime || { capabilities: {}, buildScript: null, procMacro: false, buildDependencies: [] };
    const text = bt.buildScript || bt.procMacro ? readBuildText(c.root, r) : "";
    const abilities = new Set([...Object.keys(bt.capabilities), ...extrasOf(text).map(e => e.name)]);
    const signs = r.findings.filter(f => f.category !== "web" && f.confidence !== "low" && (f.severity === "critical" || f.severity === "high"));
    return { abilities, buildScript: bt.buildScript, procMacro: bt.procMacro, buildDependencies: bt.buildDependencies, signs, verdict: r.verdict.level };
  } finally { c.cleanup(); }
}
const readBuildText = (root, r) => {
  const files = new Set(r.findings.filter(f => f.atInstall).map(f => f.file));
  const p = r.profiles.find(x => x.kind === "crate");
  for (const list of Object.values(p?.buildTime?.capabilities || {})) for (const f of list) files.add(f);
  if (p?.buildTime?.buildScript) files.add(p.buildTime.buildScript);
  return [...files].map(f => read(path.join(root, f))).join("\n");
};

/**
 * Compares two Cargo.lock texts. For every crates.io crate the update adds or changes, both
 * versions are downloaded and read (never built), and the report names what runs at build time
 * now that did not before: a new build script, new build-dependencies, new abilities, and crates
 * that only arrived with the update.
 */
export async function cargoDiff(oldText, newText, { fetch: fetchFn = fetch, vet, limit = 60, log = () => {} } = {}) {
  const ch = lockChanges(oldText, newText);
  const todo = [...ch.changed, ...ch.added].filter(ch.fromCratesIo);
  const other = [...ch.changed, ...ch.added].filter(p => !ch.fromCratesIo(p));
  const crates = [];
  // Four at a time: a hook has under a minute.
  const queue = todo.slice(0, limit), workers = Array.from({ length: Math.min(4, queue.length) }, async () => { for (let p; (p = queue.shift());) await one(p); });
  await Promise.all(workers);
  async function one(p) {
    log(`reading ${p.name} ${p.from ? `${p.from.version} -> ` : ""}${p.version}`);
    const [now, before] = await Promise.all([buildProfile(p.name, p.version, { fetch: fetchFn, vet }), p.from ? buildProfile(p.name, p.from.version, { fetch: fetchFn, vet }) : null]);
    if (!now) { crates.push({ name: p.name, from: p.from?.version || null, to: p.version, status: p.from ? "changed" : "added", requiredBy: p.requiredBy || [], error: "could not download it from crates.io (a removed version is one reason)" }); return; }
    const old = before || { abilities: new Set(), buildScript: null, procMacro: false, buildDependencies: [] };
    const runsAtBuild = !!(now.buildScript || now.procMacro);
    const gained = [...now.abilities].filter(a => !old.abilities.has(a)).sort((a, b) => CAP_ORDER.indexOf(a) - CAP_ORDER.indexOf(b));
    const e = { name: p.name, from: p.from?.version || null, to: p.version, status: p.from ? "changed" : "added", requiredBy: p.requiredBy || [],
      runsAtBuild, abilities: [...now.abilities].sort((a, b) => CAP_ORDER.indexOf(a) - CAP_ORDER.indexOf(b)), gained: p.from ? gained : [],
      newBuildScript: p.from ? !!now.buildScript && !old.buildScript : false, newProcMacro: p.from ? now.procMacro && !old.procMacro : false,
      newBuildDependencies: p.from ? now.buildDependencies.filter(d => !old.buildDependencies.includes(d)) : [],
      signs: now.signs.map(f => ({ rule: f.rule, severity: f.severity, file: f.file, line: f.line, title: f.title })), verdict: now.verdict };
    const risky = e.abilities.some(a => a !== "runs other programs" && a !== "uses the network");
    e.level = now.verdict ? "warning"
      : (p.from && (e.newBuildScript || e.newProcMacro || e.gained.length || e.newBuildDependencies.length)) || (!p.from && runsAtBuild && (e.abilities.includes("uses the network") || risky)) || e.signs.length ? "look" : "ok";
    crates.push(e);
  }
  const rank = { warning: 0, look: 1, ok: 2 };
  crates.sort((a, b) => (rank[a.level] ?? 1) - (rank[b.level] ?? 1) || a.name.localeCompare(b.name));
  return { added: ch.added.length, changed: ch.changed.length, removed: ch.removed.map(p => `${p.name} ${p.version}`), crates,
    skipped: todo.slice(limit).map(p => `${p.name} ${p.version}`), notCratesIo: other.map(p => `${p.name} ${p.version} (${p.source || "path"})`),
    level: crates.some(c => c.level === "warning") ? "warning" : crates.some(c => c.level === "look" || c.error) ? "look" : "ok" };
}

/** The diff as Markdown, for the terminal and for an agent. */
export function cargoDiffMarkdown(d, label = "") {
  const out = [`# vetcode: what a Cargo.lock update brings in${label ? ` (${label})` : ""}`, "",
    `${d.changed} crate${d.changed === 1 ? "" : "s"} changed, ${d.added} added, ${d.removed.length} removed. Each changed or added crate from crates.io was downloaded and read; nothing was built or run.`, ""];
  const head = { warning: "## Do not build yet", look: "## Worth a look before building", ok: "## Nothing new at build time" };
  for (const level of ["warning", "look"]) {
    const list = d.crates.filter(c => c.level === level || (level === "look" && c.error));
    if (!list.length) continue;
    out.push(head[level], "");
    for (const c of list) {
      const what = c.status === "added" ? `**${c.name} ${c.to}**, new${c.requiredBy.length ? `, required by ${c.requiredBy.join(", ")}` : ""}` : `**${c.name} ${c.from} → ${c.to}**`;
      if (c.error) { out.push(`- ${what}: ${c.error}.`); continue; }
      const bits = [];
      if (c.newBuildScript) bits.push("now has a build script");
      if (c.newProcMacro) bits.push("is now a procedural macro");
      if (c.newBuildDependencies.length) bits.push(`new build-dependencies: ${c.newBuildDependencies.join(", ")}`);
      if (c.gained.length) bits.push(`its build-time code now ${c.gained.join(", ")}`);
      if (c.status === "added" && c.runsAtBuild) bits.push(`runs at build time and ${c.abilities.join(", ") || "has no notable abilities"}`);
      out.push(`- ${what}: ${bits.join("; ") || "see the signs below"}.`);
      for (const s of c.signs.slice(0, 4)) out.push(`  - ${s.severity}: ${s.title} (\`${s.file}:${s.line}\`)`);
    }
    out.push("");
  }
  const quiet = d.crates.filter(c => c.level === "ok");
  if (quiet.length) out.push(head.ok, "", quiet.map(c => `${c.name} ${c.from ? `${c.from} → ` : ""}${c.to}`).join(", "), "");
  if (d.skipped.length) out.push(`Not read (more than the limit): ${d.skipped.join(", ")}.`, "");
  if (d.notCratesIo.length) out.push(`Not from crates.io, not read: ${d.notCratesIo.join(", ")}.`, "");
  return out.join("\n");
}

// Commands that build (run build scripts and proc macros) and commands that change Cargo.lock.
export const CARGO_BUILDS = /(?:^|[\s;&|(])cargo\s+(?:\+\S+\s+)?(?:build|b|check|c|run|r|test|t|bench|clippy|doc|nextest)(?=$|[\s;&|)])/;
export const CARGO_LOCKS = /(?:^|[\s;&|(])cargo\s+(?:\+\S+\s+)?(?:update|add|generate-lockfile|upgrade)(?=$|[\s;&|)])/;

/** The Cargo.lock in or above cwd against the committed one, when they differ. */
export function lockSinceHead(cwd, { spawnSync }) {
  const top = spawnSync("git", ["-C", cwd, "rev-parse", "--show-toplevel"], { encoding: "utf8" });
  if (top.status !== 0) return null;
  const real = p => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
  const root = real(top.stdout.trim());
  let dir = real(cwd);
  while (!fs.existsSync(path.join(dir, "Cargo.lock")) && dir.startsWith(root) && dir !== root) dir = path.dirname(dir);
  const abs = path.join(dir, "Cargo.lock");
  if (!fs.existsSync(abs)) return null;
  const rel = path.relative(root, abs).split(path.sep).join("/");
  const head = spawnSync("git", ["-C", root, "show", `HEAD:${rel}`], { encoding: "utf8", maxBuffer: 64 << 20 });
  const now = read(abs);
  const before = head.status === 0 ? head.stdout : "";
  return before === now ? null : { before, after: now, rel };
}

/** For the guard: a short message, and whether to stop, ask or just tell. Null when nothing is worth saying. */
export async function cargoLockCheck(cwd, { spawnSync, vet, limit = 8 }) {
  const lock = lockSinceHead(cwd, { spawnSync });
  if (!lock) return null;
  const d = await cargoDiff(lock.before, lock.after, { vet, limit });
  const worth = d.crates.filter(c => c.level !== "ok");
  if (!worth.length && !d.skipped.length) return null;
  const line = c => {
    const what = c.status === "added" ? `${c.name} ${c.to} (new${c.requiredBy?.length ? `, required by ${c.requiredBy.join(", ")}` : ""})` : `${c.name} ${c.from} -> ${c.to}`;
    if (c.error) return `${what}: ${c.error}.`;
    const bits = [c.verdict ? `vetcode's verdict: ${c.signs[0]?.title || "malicious"}` : null, c.newBuildScript && "now has a build script", c.newProcMacro && "is now a procedural macro",
      c.newBuildDependencies.length && `new build-dependencies ${c.newBuildDependencies.join(", ")}`, c.gained.length && `build-time code now ${c.gained.join(", ")}`,
      c.status === "added" && c.runsAtBuild && `runs at build time and ${c.abilities.join(", ")}`].filter(Boolean);
    return `${what}: ${bits.join("; ")}.`;
  };
  const text = [`vetcode: ${lock.rel} differs from the last commit, and building runs these crates' build scripts and proc macros.`, ...worth.slice(0, 6).map(line),
    ...(d.skipped.length ? [`${d.skipped.length} more changed crate${d.skipped.length === 1 ? " was" : "s were"} not read in time.`] : []),
    "Full report: vetcode --cargo-diff HEAD. Nothing was built or run."].join(" ");
  return { level: d.level === "warning" ? "deny" : "ask", text, diff: d };
}
