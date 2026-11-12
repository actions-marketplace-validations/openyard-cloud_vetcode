#!/usr/bin/env node
// Builds what the MCP Registry and Claude Desktop need from this repository:
//
//   vetcode.mcpb   an MCP bundle (a zip): the server, the skill it reads, and a manifest.
//                  Opened in Claude Desktop, it installs the server; the registry points at it.
//   server.json    the registry entry for this version, with the bundle's address and hash.
//
//   node .github/mcp/bundle.mjs <folder>                 build both
//   node .github/mcp/bundle.mjs <folder> <vetcode.mcpb>  write server.json for a bundle that is
//                                                        already on the release
//
// The Release workflow runs it once per version, attaches vetcode.mcpb to the release and
// publishes server.json. The registry keeps the hash, so a bundle is never replaced afterwards.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
if (!process.argv[2]) { console.error("usage: node .github/mcp/bundle.mjs <folder> [vetcode.mcpb]"); process.exit(2); }
const out = path.resolve(process.argv[2]);
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const REPO = "https://github.com/openyard-cloud/vetcode";

fs.rmSync(out, { recursive: true, force: true });
const dir = path.join(out, "bundle");
fs.mkdirSync(path.join(dir, "mcp"), { recursive: true });
fs.copyFileSync(path.join(root, "mcp/server.mjs"), path.join(dir, "mcp/server.mjs"));
fs.cpSync(path.join(root, "skills"), path.join(dir, "skills"), { recursive: true, filter: f => path.basename(f) !== ".DS_Store" });
for (const f of ["LICENSE", "PRIVACY.md"]) fs.copyFileSync(path.join(root, f), path.join(dir, f));
fs.copyFileSync(path.join(root, ".github/mcp/icon.png"), path.join(dir, "icon.png"));

// The tools as the server declares them, so the manifest cannot drift from the code.
const source = fs.readFileSync(path.join(root, "mcp/server.mjs"), "utf8");
const tools = [...source.matchAll(/^\s+name: "(vetcode_\w+)",\n\s+description: "((?:[^"\\]|\\.)*)"/gm)].map(m => ({ name: m[1], description: JSON.parse(`"${m[2]}"`).split(/(?<=\.)\s/)[0] }));
if (tools.length !== 4) throw new Error(`expected 4 tools in mcp/server.mjs, found ${tools.length}`);

const manifest = {
  manifest_version: "0.3",
  name: "vetcode",
  display_name: "vetcode",
  version: pkg.version,
  description: "Security check for coding agents: scans a folder and checks packages before they install. Reads, never runs.",
  long_description: "vetcode gives an agent a scanner for malware, supply-chain attacks, attacks on AI agents, leaked secrets and web or server vulnerabilities, a guard that answers allow, ask or deny for a command that would install packages, and the review procedure to confirm each finding. It has no dependencies and never installs, builds or runs anything from the code it reads. The scanner sends nothing unless asked to look dependencies up on OSV.dev; the guard sends package names and versions to the package registry and OSV.dev.",
  author: { name: "OpenYard", url: "https://openyard.cloud" },
  repository: { type: "git", url: `${REPO}.git` },
  homepage: REPO,
  documentation: `${REPO}#mcp-server`,
  support: `${REPO}/issues`,
  icon: "icon.png",
  server: { type: "node", entry_point: "mcp/server.mjs", mcp_config: { command: "node", args: ["${__dirname}/mcp/server.mjs"], env: {} } },
  tools,
  prompts: [{ name: "security_review", description: "Run a vetcode security review of a folder: scan, confirm, review by hand, report.", arguments: ["path", "goal"], text: "Review ${arguments.path} for security problems with vetcode. Goal: ${arguments.goal}" }],
  keywords: ["security", "malware", "supply-chain", "secrets", "sast", "code-review"],
  license: pkg.license,
  privacy_policies: [`${REPO}/blob/main/PRIVACY.md`],
  compatibility: { platforms: ["darwin", "linux", "win32"], runtimes: { node: ">=18.0.0" } },
};
fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

// One archive for one version: fixed file times and a fixed order, so building it twice gives the same bytes.
const files = [];
(function walk(rel) {
  for (const e of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const p = path.join(rel, e.name);
    if (e.isDirectory()) walk(p); else { files.push(p); fs.utimesSync(path.join(dir, p), new Date("2020-01-01T00:00:00Z"), new Date("2020-01-01T00:00:00Z")); }
  }
})("");
files.sort();
const archive = path.join(out, "vetcode.mcpb");
if (process.argv[3]) fs.copyFileSync(path.resolve(process.argv[3]), archive);
else {
  const zip = spawnSync("zip", ["-X", "-q", "-9", archive, "-@"], { cwd: dir, input: files.join("\n") + "\n", encoding: "utf8", env: { ...process.env, TZ: "UTC" } });
  if (zip.status !== 0) throw new Error(`zip failed: ${zip.stderr || zip.error}`);
}
const sha = crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex");

const server = {
  $schema: "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  name: "io.github.openyard-cloud/vetcode",
  title: "vetcode",
  description: "Security check for coding agents: malware, supply chain, secrets and web bugs. Reads, never runs.",
  version: pkg.version,
  repository: { url: REPO, source: "github" },
  packages: [{ registryType: "mcpb", identifier: `${REPO}/releases/download/v${pkg.version}/vetcode.mcpb`, version: pkg.version, fileSha256: sha, transport: { type: "stdio" } }],
};
fs.writeFileSync(path.join(out, "server.json"), JSON.stringify(server, null, 2) + "\n");
console.log(`vetcode.mcpb ${pkg.version}: ${files.length} files, ${fs.statSync(archive).size} bytes, sha256 ${sha}`);
