// What a file can do, GuardDog-style: one capability is normal, but code that runs at
// install time and both reads secrets and talks to the network (or runs programs, or
// decodes hidden code) is how most package malware is built.
import fs from "node:fs";
import path from "node:path";
import { finding } from "./engine.mjs";

const CAPS = {
  "reads environment or credential files": /process\.env\b|os\.environ|os\.getenv|\.ssh[\\/]|\.npmrc|\.aws[\\/]|\.git-credentials|homedir\(\)|expanduser\(["']~/,
  "uses the network": /\bfetch\s*\(|https?\.(?:get|request)\s*\(|require\(["'](?:node:)?(?:https?|net|dgram|dns)["']\)|from\s+["'](?:node:)?(?:https?|net|dgram|dns)["']|\baxios\b|\bXMLHttpRequest\b|\bWebSocket\b|requests\.(?:get|post)|urllib\.request|urlopen|\bsocket\.socket|httpx\./,
  "runs other programs": /child_process|\bexecSync\b|\bspawnSync?\b|subprocess\.|os\.system|os\.popen/,
  "decodes or builds code at runtime": /\batob\s*\(|Buffer\.from\([^)]*["']base64["']|base64\.b64decode|String\.fromCharCode|\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*(?:compile|base64|zlib|marshal)/,
};

export function capabilitiesOf(text) {
  return Object.entries(CAPS).filter(([, re]) => re.test(text)).map(([name]) => name);
}

// Files a package runs at install: "node scripts/x.js", "python setup.py", "sh ./install.sh".
export function installEntryFiles(dir, scripts) {
  const files = new Set();
  for (const cmd of Object.values(scripts || {})) {
    for (const m of String(cmd).matchAll(/(?:^|[\s;&|])(?:node|nodejs|bun|deno\s+run(?:\s+-\S+)*|python\d?|sh|bash)\s+(?:-\S+\s+)*["']?([\w./@-]+\.(?:c?m?js|ts|py|sh))/g)) files.add(path.join(dir, m[1]));
  }
  if (fs.existsSync(path.join(dir, "setup.py"))) files.add(path.join(dir, "setup.py"));
  return [...files].filter(f => f.startsWith(dir) && fs.existsSync(f));
}

export function checkInstallEntry(abs, rel, out, installed) {
  let text; try { text = fs.readFileSync(abs, "utf8"); } catch { return; }
  const caps = capabilitiesOf(text);
  const net = caps.includes("uses the network");
  const risky = caps.filter(c => c !== "uses the network");
  if (!net || !risky.length) return;
  out.push(finding({ id: "install-time-capabilities", category: "supply-chain", severity: risky.length >= 2 || installed ? "critical" : "high", confidence: "medium",
    title: "Install-time code combines network access with secrets, programs or hidden code",
    why: `This file runs during install and ${caps.join(", ")}. That combination is the shape of nearly every credential-stealing package.`,
    fix: "Read the whole file before installing. If it is a dependency, install with --ignore-scripts until it is explained." }, rel, 1, caps.join(" + ")));
}
