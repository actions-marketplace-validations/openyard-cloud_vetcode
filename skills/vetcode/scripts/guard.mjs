#!/usr/bin/env node
// vetcode guard: checks what a shell command would install before it runs.
//
// As a Claude Code hook (PreToolUse on Bash, see hooks/hooks.json) it reads the hook's JSON on
// stdin and answers allow, ask or deny. By hand:
//
//   node guard.mjs "npm install expres"        # prints the decision and the reasons
//   echo '{"tool_name":"Bash","tool_input":{"command":"pip install requessts"}}' | node guard.mjs
//
// Settings (environment):
//   VETCODE_GUARD=off       do nothing
//   VETCODE_GUARD=strict    turn every "ask" into "deny"
//   VETCODE_GUARD_MIN_AGE_HOURS=72   how old a release must be before it installs without a question
//
// What leaves the machine: the names and versions of the packages in the command, to the
// package registry (npm, PyPI) and to OSV.dev, and a download of the package archive, which is
// read and deleted. The install itself would contact the same registry. Nothing is executed.
// If the network is down or a check fails, the command is allowed: the guard never blocks on
// its own errors. Packages that come from a private registry (a registry line in .npmrc, or
// PIP_INDEX_URL and the like) are not looked up anywhere.

const MODE = (process.env.VETCODE_GUARD || "on").toLowerCase();
// Most shell commands install nothing: decide that before doing any work.
const MAYBE = /\b(?:npm|pnpm|yarn|bun|npx|bunx|pnpx|pip[\d.]*|uv|uvx|pipx|poetry)\b|\b(?:curl|wget)\b[^|]*\|/;

async function main() {
  const arg = process.argv[2];
  let command = arg, hook = false, cwd = process.cwd();
  if (!arg) {
    let input = ""; for await (const chunk of process.stdin) input += chunk;
    let j; try { j = JSON.parse(input); } catch { return; }
    if (j.tool_name !== "Bash") return;
    command = j.tool_input?.command || ""; cwd = j.cwd || cwd; hook = true;
  }
  if (MODE === "off" || !command || !MAYBE.test(command)) return;
  // The scanner is loaded only now: every other shell command pays for a regex, nothing more.
  const [{ guard, scanArchive, privateRegistries }, { vet }] = await Promise.all([import("./lib/guard.mjs"), import("./lib/index.mjs")]);
  const res = await guard(command, { cwd, mode: MODE, minAgeHours: +(process.env.VETCODE_GUARD_MIN_AGE_HOURS || 72), isPrivate: privateRegistries({ cwd }), scan: (eco, url, size) => scanArchive(eco, url, size, { vet }) });
  if (!hook) {
    console.log(`${res.decision}${res.checked ? ` (${res.checked} package${res.checked === 1 ? "" : "s"} checked)` : ""}`);
    if (res.message) console.log(res.message);
    for (const n of res.notes) console.log(`note: ${n}`);
    process.exitCode = res.decision === "deny" ? 2 : res.decision === "ask" ? 1 : 0;
    return;
  }
  if (res.decision === "allow") {
    // Say nothing unless there is something worth knowing; the agent sees it with the result.
    if (res.notes.length) console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: `vetcode checked this install. ${res.notes.join(" ")}` } }));
    return;
  }
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: res.decision, permissionDecisionReason: res.message } }));
}

// A guard that fails must not stop the work: any error means "no opinion".
main().catch(() => {});
