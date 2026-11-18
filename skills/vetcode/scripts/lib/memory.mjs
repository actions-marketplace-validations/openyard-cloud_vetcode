// Memory provenance. Agents write their own long-term memory (MEMORY.md and the files it indexes,
// CLAUDE.md, AGENTS.md, GEMINI.md, Cursor and Windsurf rules), and every later session loads it.
// An injected instruction reads like an ordinary one, so this does not judge what the text says
// (bench/README.md measured why that fails). It asks where the text came from: the session
// transcript records what the person typed, what the assistant wrote, and what each tool returned.
//
// Part A: before a memory write, the concrete pieces of the lines being added (URLs, domains,
// IP addresses, emails, commands, packages, paths outside the project, environment variable
// names) are traced. A piece that first appeared in a tool result and never in anything the
// person typed is named, with its source. An instruction with no concrete piece is not seen.
//
// Part B: after each memory write the hook allowed, the file's hash goes into a ledger; at the
// start of a session, memory files and the hooks in ~/.claude/settings.json are compared with
// it, and what changed without an agent write is reported. It cannot tell a person's own edit
// from an attacker's; it says what changed.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const HOME = os.homedir();
const MEMORY_FILE = /(?:^|[\\/])(?:MEMORY|CLAUDE|CLAUDE\.local|AGENTS|GEMINI)\.md$|(?:^|[\\/])\.cursor[\\/]rules[\\/][^\\/]+$|(?:^|[\\/])\.(?:cursorrules|windsurfrules)$|(?:^|[\\/])\.claude[\\/]projects[\\/][^\\/]+[\\/]memory[\\/][^\\/]+\.md$/;
/** Files whose contents an agent loads into later sessions (also under CLAUDE_CONFIG_DIR when it is set). */
export const isMemoryFile = file => {
  const f = String(file || "");
  if (MEMORY_FILE.test(f)) return true;
  const dir = process.env.CLAUDE_CONFIG_DIR;
  return !!dir && f.startsWith(path.join(dir, "projects") + path.sep) && /[\\/]memory[\\/][^\\/]+\.md$/.test(f);
};

// ---- the transcript ----

const textOf = c => typeof c === "string" ? c : Array.isArray(c) ? c.map(b => b?.type === "text" ? b.text : b?.type === "tool_result" ? textOf(b.content) : "").join("\n") : "";
// What a tool was pointed at, for the message: the URL fetched, the file read, the command run, the MCP server.
const targetOf = (name, input = {}) => input.url || input.file_path || input.path || input.notebook_path || input.command || input.query || input.pattern || (name.startsWith("mcp__") ? name.split("__")[1] : "") || "";
// Results the agent produced itself: writing a file returns the file.
const OWN_TOOLS = /^(?:Write|Edit|MultiEdit|NotebookEdit|TodoWrite|TaskCreate|TaskUpdate|ExitPlanMode|EnterPlanMode)$/;

/** An empty view of a transcript, filled record by record with addRecord. */
export const transcriptState = () => ({ user: [], assistant: [], tools: [], uses: new Map(), order: 0 });

/**
 * One transcript record into the view, by source: what the person typed (typed prompts, prompts
 * typed while the agent worked), what the assistant wrote, and each tool result with its tool and
 * target, in order. Returns the tool calls the record makes, so a replay can stop at one.
 */
export function addRecord(st, e) {
  const m = e?.message || {}, calls = [];
  if (e?.type === "assistant" && Array.isArray(m.content)) {
    for (const b of m.content) {
      if (b?.type === "tool_use") { st.uses.set(b.id, { name: b.name, input: b.input || {} }); calls.push({ id: b.id, name: b.name, input: b.input || {} }); }
      else if (b?.type === "text" && b.text) st.assistant.push({ text: b.text, at: st.order++ });
    }
  } else if (e?.type === "user") {
    if (Array.isArray(m.content) && m.content.some(b => b?.type === "tool_result")) {
      for (const b of m.content) if (b?.type === "tool_result") {
        const u = st.uses.get(b.tool_use_id) || { name: "tool", input: {} };
        if (!OWN_TOOLS.test(u.name)) st.tools.push({ tool: u.name, target: String(targetOf(u.name, u.input)).slice(0, 200), text: textOf(b.content), at: st.order++ });
      }
    } else if (e.origin?.kind === "human" && !e.isMeta) st.user.push({ text: textOf(m.content), at: st.order++ });
  } else if (e?.type === "attachment") {
    const a = e.attachment || {};
    if (a.type === "queued_command" && a.origin?.kind === "human" && !a.isMeta) st.user.push({ text: textOf(a.prompt), at: st.order++ });
  }
  return calls;
}
// Transcripts reach hundreds of megabytes, mostly copies of requests: only these records are parsed.
export const worthParsing = line => line.length < 20e6 && (line.includes('"type":"assistant"') || line.includes('"type":"user"') || line.includes('"queued_command"'));

/** The whole transcript as that view, up to (not including) the tool call `stopAt`. */
export async function readTranscript(file, { stopAt } = {}) {
  const st = transcriptState();
  if (!file || !fs.existsSync(file)) return st;
  const readline = await import("node:readline");
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: "utf8" }), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!worthParsing(line)) continue;
    let e; try { e = JSON.parse(line); } catch { continue; }
    if (stopAt && e.type === "assistant" && Array.isArray(e.message?.content) && e.message.content.some(b => b?.type === "tool_use" && b.id === stopAt)) {
      // What the assistant wrote in the same message, before the call, still counts.
      for (const b of e.message.content) { if (b?.type === "tool_use" && b.id === stopAt) break; if (b?.type === "text" && b.text) st.assistant.push({ text: b.text, at: st.order++ }); }
      rl.close(); return st;
    }
    addRecord(st, e);
  }
  return st;
}

// ---- concrete pieces ----

// Top-level domains that are also file extensions (.md, .sh, .py, .rs, .ts) are left out: README.md is not a domain.
const TLD = "com|net|org|io|dev|app|cloud|xyz|ru|cn|top|site|info|me|co|ai|link|online|store|tech|biz|us|uk|de|fr|jp|kr|vn|in|br|pw|cc|tk|ml|ga|cf|gq|live|space|website|click|fun|icu|cyou|buzz|ngrok|pages|workers|run|page|so|gg|to|ly|tv|su|ws|ps|ir|ng";
const URL_RE = /\bhttps?:\/\/[^\s<>()\[\]"'`]+/gi;
const DOMAIN_RE = new RegExp(`\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:${TLD})\\b(?![.\\w-]*\\.(?:md|json|js|mjs|ts|py|rs|sh|txt|toml|ya?ml)\\b)`, "gi");
const IP_RE = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
const EMAIL_RE = /\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi;
const ENV_RE = /\b[A-Z][A-Z0-9]*_[A-Z0-9_]{2,}\b/g;
const CMD_RE = /`([^`\n]{4,200})`|^\s*(?:\$\s+)?((?:curl|wget|npm|npx|pnpm|yarn|bun|pip3?|pipx|uvx?|cargo|go|git\s+clone|bash|sh|zsh|powershell|pwsh|iwr|irm|docker|brew|apt(?:-get)?|chmod|nc)\b[^\n]{2,200})$/gim;
const COMMAND_WORD = /^(?:sudo\s+)?(?:curl|wget|npm|npx|pnpm|yarn|bun|pip3?|pipx|uvx?|cargo|go|git|gh|bash|sh|zsh|powershell|pwsh|iwr|irm|docker|brew|apt(?:-get)?|chmod|nc|node|python3?|deno|claude|gemini|codex)\b/;
const INSTALL_RE = /\b(?:npm\s+(?:i|install|add)|pnpm\s+add|yarn\s+add|bun\s+add|pip3?\s+install|uv\s+(?:add|pip\s+install)|uvx|pipx\s+(?:install|run)|cargo\s+(?:add|install)|go\s+(?:get|install)|npx)\s+((?:-{1,2}[\w-]+(?:=\S+)?\s+)*)([@\w./-]+)/g;
const PATH_RE = /(?:^|[\s`"'(=])((?:~|\$HOME|%APPDATA%|%USERPROFILE%)[\\/][^\s`"')]+|\/(?:etc|usr|var|tmp|opt|Users|home|root|Library|private)\/[^\s`"')]+)/g;
const COMMON_ENV = new Set(["CLAUDE_PLUGIN_ROOT", "CLAUDE_PROJECT_DIR", "NODE_ENV", "GITHUB_TOKEN", "GITHUB_ACTIONS", "RUNNER_TEMP", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_STEP_SUMMARY", "GITHUB_OUTPUT", "CI", "TODO", "FIXME", "README_MISSING"]);

const trimUrl = u => u.replace(/[.,;:!?'")\]]+$/, "");
/** The concrete pieces of a text: what an instruction to send somewhere or to run something has to name. */
export function piecesOf(text) {
  const out = new Map();
  const add = (kind, value, show = value) => { const key = `${kind}:${value.toLowerCase()}`; if (!out.has(key)) out.set(key, { kind, value: value.toLowerCase(), show }); };
  const urls = [...text.matchAll(URL_RE)].map(m => trimUrl(m[0]));
  // A URL stands for its domain; a domain is a piece of its own only where it is written bare.
  for (const u of urls) add("url", u);
  const noUrls = text.replace(URL_RE, " ");
  for (const m of noUrls.matchAll(EMAIL_RE)) add("email", m[0]);
  const noMail = noUrls.replace(EMAIL_RE, " ");
  for (const m of noMail.matchAll(DOMAIN_RE)) add("domain", m[0].replace(/^www\./i, ""));
  // Loopback and private ranges are local; four small numbers (1.2.3.4) are a version, not an address.
  for (const m of text.matchAll(IP_RE)) if (!/^(?:127|10|0)\.|^192\.168\.|^169\.254\./.test(m[0]) && !m[0].split(".").every(n => +n < 10)) add("ip", m[0]);
  for (const m of text.matchAll(ENV_RE)) if (!COMMON_ENV.has(m[0])) add("env", m[0]);
  for (const m of text.matchAll(CMD_RE)) { const c = (m[1] || m[2]).trim().replace(/\s+/g, " "); if (COMMAND_WORD.test(c)) add("command", c); }
  for (const m of text.matchAll(INSTALL_RE)) if (!m[2].startsWith("-")) add("package", m[2].replace(/[.,;:]+$/, ""));
  for (const m of text.matchAll(PATH_RE)) add("path", m[1].replace(/[.,;:]+$/, ""));
  return [...out.values()];
}

// ---- deciding ----

const norm = s => s.toLowerCase();
const has = (text, piece) => {
  const t = norm(text);
  if (piece.kind === "command") return t.replace(/\s+/g, " ").includes(piece.value);
  if (piece.kind === "url") return t.includes(piece.value) || t.includes(piece.value.replace(/^https?:\/\//, ""));
  if (piece.kind === "domain") return new RegExp(`(?:^|[^a-z0-9.-])(?:www\\.)?${piece.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![a-z0-9-])`).test(t);
  return t.includes(piece.value);
};

/** What the project owns: its folder, and its GitHub owner (from git's origin), so its own links are not foreign. */
export function projectOf(cwd, { spawnSync } = {}) {
  let owner = null;
  try {
    const r = spawnSync?.("git", ["-C", cwd, "remote", "get-url", "origin"], { encoding: "utf8" });
    const m = /github\.com[:/]([\w.-]+)\//i.exec(r?.stdout || "");
    if (m) owner = m[1].toLowerCase();
  } catch {}
  return { cwd: cwd ? path.resolve(cwd) : null, owner };
}
const ownedBy = (piece, project) => {
  if (!project) return false;
  if (project.owner && piece.kind === "url" && new RegExp(`^https?://(?:www\\.)?github\\.com/${project.owner}(?:/|$)`, "i").test(piece.value)) return true;
  if (piece.kind === "path" && project.cwd) { const p = piece.value.replace(/^~|^\$home/i, HOME.toLowerCase()); if (p.startsWith(project.cwd.toLowerCase())) return true; }
  return false;
};

/** The lines a write adds: for Edit and MultiEdit the new strings, for Write the lines the file did not have. */
export function addedText(tool, input = {}, before = "") {
  if (tool === "Edit") return String(input.new_string || "");
  if (tool === "MultiEdit") return (input.edits || []).map(e => e?.new_string || "").join("\n");
  const had = new Set(String(before || "").split("\n").map(l => l.trim()));
  return String(input.content || "").split("\n").filter(l => l.trim() && !had.has(l.trim())).join("\n");
}

/**
 * Where each concrete piece of a memory write came from. Returns the pieces that first appeared in
 * a tool result and never in anything the person typed, each with the tool and target it came from.
 */
export function foreignPieces(added, transcript, project) {
  const found = [];
  for (const piece of piecesOf(added)) {
    if (ownedBy(piece, project)) continue;
    if (transcript.user.some(u => has(u.text, piece))) continue;
    const tool = transcript.tools.find(t => has(t.text, piece) || has(t.target, piece));
    if (!tool) continue;
    // Said by the assistant before any tool showed it: the agent's own words, not a relay.
    const said = transcript.assistant.find(a => has(a.text, piece));
    if (said && said.at < tool.at) continue;
    found.push({ ...piece, tool: tool.tool, target: tool.target });
  }
  return found;
}

/** The question for the person, naming each piece and where it came from. */
export function provenanceMessage(file, pieces) {
  const src = p => `${p.tool}${p.target ? ` of ${p.target.length > 90 ? p.target.slice(0, 87) + "…" : p.target}` : ""}`;
  const list = pieces.slice(0, 4).map(p => `\`${p.show.length > 80 ? p.show.slice(0, 77) + "…" : p.show}\` (${p.kind}, from ${src(p)})`).join("; ");
  return `vetcode: this write to ${path.basename(file)} saves ${pieces.length === 1 ? "something" : `${pieces.length} things`} that came from a tool result and not from anything you typed: ${list}${pieces.length > 4 ? `, and ${pieces.length - 4} more` : ""}. Memory is loaded into every later session, so text a page or a tool put there outlives it. Allow it if you meant the agent to keep this.`;
}

// ---- Part B: the ledger ----

const digest = s => crypto.createHash("sha256").update(s).digest("hex").slice(0, 24);
const configDir = () => process.env.CLAUDE_CONFIG_DIR || path.join(HOME, ".claude");
export const ledgerPath = () => path.join(configDir(), "vetcode", "memory-ledger.json");
const readLedger = file => { try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return null; } };
const writeLedger = (file, data) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(data, null, 1) + "\n"); };
const lines = s => s ? s.split("\n").length : 0;

// Claude Code keeps a project's memory under ~/.claude/projects/<the project path with / as ->/memory.
const projectKey = cwd => path.resolve(cwd).replace(/[^A-Za-z0-9]/g, "-");

/** The memory and instruction files that load into a session in cwd, and the hooks Claude Code runs. */
export function trackedFiles(cwd) {
  const out = [];
  const add = f => { try { if (fs.statSync(f).isFile()) out.push(f); } catch {} };
  const mem = path.join(configDir(), "projects", projectKey(cwd), "memory");
  try { for (const n of fs.readdirSync(mem)) if (n.endsWith(".md")) add(path.join(mem, n)); } catch {}
  for (const n of ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", path.join(".claude", "CLAUDE.md")]) add(path.join(cwd, n));
  try { for (const n of fs.readdirSync(path.join(cwd, ".cursor", "rules"))) add(path.join(cwd, ".cursor", "rules", n)); } catch {}
  add(path.join(configDir(), "CLAUDE.md"));
  return out;
}
const HOOKS = "hooks in " + path.join("~", ".claude", "settings.json");
function hooksText() {
  try { const j = JSON.parse(fs.readFileSync(path.join(configDir(), "settings.json"), "utf8")); return JSON.stringify(j.hooks || {}, null, 1); } catch { return null; }
}
const snapshot = file => { try { const t = fs.readFileSync(file, "utf8"); return { hash: digest(t), lines: lines(t) }; } catch { return null; } };

/** After a write the hook allowed: the file as the agent left it. */
export function recordWrite(file, { ledger = ledgerPath() } = {}) {
  const l = readLedger(ledger) || { note: "vetcode memory ledger: each memory file and the Claude Code hooks as an agent or the last session start left them.", files: {} };
  const s = snapshot(file);
  if (s) l.files[path.resolve(file)] = s; else delete l.files[path.resolve(file)];
  writeLedger(ledger, l);
}

/**
 * At session start: what changed in memory files and in the hooks since the ledger, without an
 * agent write. The first run only takes the snapshot. Returns a message, or null.
 */
export function changesSinceLedger(cwd, { ledger = ledgerPath() } = {}) {
  const l = readLedger(ledger);
  const now = {};
  for (const f of trackedFiles(cwd)) now[path.resolve(f)] = snapshot(f);
  const hooks = hooksText();
  if (hooks != null) now[HOOKS] = { hash: digest(hooks), lines: lines(hooks) };
  const first = !l;
  const was = l?.files || {};
  const changed = [];
  for (const [f, s] of Object.entries(now)) {
    if (!s) continue;
    const w = was[f];
    if (!w) { if (!first && f !== HOOKS) changed.push({ f, what: `new, ${s.lines} line${s.lines === 1 ? "" : "s"}` }); else if (!first && f === HOOKS) changed.push({ f, what: "hooks added" }); continue; }
    if (w.hash !== s.hash) changed.push({ f, what: `${s.lines - w.lines >= 0 ? "+" : ""}${s.lines - w.lines} lines` });
  }
  const next = { note: "vetcode memory ledger: each memory file and the Claude Code hooks as an agent or the last session start left them.", files: { ...was, ...Object.fromEntries(Object.entries(now).filter(([, s]) => s)) } };
  writeLedger(ledger, next);
  if (first || !changed.length) return null;
  const name = f => f === HOOKS ? HOOKS : f.startsWith(HOME) ? "~" + f.slice(HOME.length) : f;
  const memory = changed.filter(c => c.f !== HOOKS).length, hookChange = changed.some(c => c.f === HOOKS);
  return `vetcode: ${[memory ? `${memory} memory or instruction file${memory === 1 ? "" : "s"}` : "", hookChange ? "the Claude Code hooks" : ""].filter(Boolean).join(" and ")} changed since the last session without an agent write: ${changed.slice(0, 6).map(c => `${name(c.f)} (${c.what})`).join("; ")}${changed.length > 6 ? `; and ${changed.length - 6} more` : ""}. Every session loads ${memory ? "memory" : "these hooks"}, so read the change before relying on it. If you edited ${changed.length === 1 ? "it" : "them"} yourself, ignore this.`;
}
