#!/bin/sh
# Builds the folder that is published as the Claude Code plugin on the `plugin` branch, which
# is the one the Claude plugin directory follows. Nothing else from this repository
# (benchmarks, tests, the GitHub Action, the MCP server) is part of it.
#
#   sh .github/plugin/build.sh <folder>            build it
#   sh .github/plugin/build.sh <folder> <remote>   build it, then commit it to the remote's
#                                                  `plugin` branch when anything in it changed
#
# Two editions:
#   default        the skill alone: Markdown, no programs, no hooks. The directory accepts
#                  programs and hooks only from organizations it has verified.
#   WITH_CODE=1    the whole plugin: skill, scanner, guard and hooks. Set it in the Release
#                  workflow once the organization that submits the plugin is verified.
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$1"
remote="${2:-}"

rm -rf "$out"
mkdir -p "$out/.claude-plugin"
cp "$root/.claude-plugin/plugin.json" "$root/.claude-plugin/icon.png" "$out/.claude-plugin/"
cp "$root/LICENSE" "$root/PRIVACY.md" "$root/SECURITY.md" "$out/"
if [ "${WITH_CODE:-}" = "1" ]; then
  cp -R "$root/skills" "$root/hooks" "$out/"
  cp "$root/.github/plugin/README.md" "$out/README.md"
else
  mkdir -p "$out/skills/vetcode"
  cp "$root/skills/vetcode/SKILL.md" "$out/skills/vetcode/"
  cp -R "$root/skills/vetcode/references" "$out/skills/vetcode/"
  cp "$root/.github/plugin/README.skill-only.md" "$out/README.md"
  # The listing takes its short description from the manifest: say what this edition is.
  node -e '
    const fs = require("fs"), f = process.argv[1], m = JSON.parse(fs.readFileSync(f, "utf8"));
    m.description = "Security review skill for coding agents: a procedure and checklists for finding malware, supply-chain attacks, leaked secrets, web/API vulnerabilities and server misconfiguration by reading code. Skill only: the scanner and the install guard are in the full plugin on GitHub.";
    fs.writeFileSync(f, JSON.stringify(m, null, 2) + "\n");
  ' "$out/.claude-plugin/plugin.json"
fi
find "$out" -name .DS_Store -delete

[ -n "$remote" ] || exit 0

v="$(node -p 'JSON.parse(require("fs").readFileSync(0, "utf8")).version' < "$out/.claude-plugin/plugin.json")"
cd "$out"
git init -q -b plugin
if git fetch -q --depth 1 "$remote" plugin 2>/dev/null; then git reset -q --soft FETCH_HEAD; fi
git add -A
if git rev-parse -q --verify HEAD >/dev/null; then
  if git diff --cached --quiet HEAD; then
    echo "The plugin branch already holds this ($v)."
    exit 0
  fi
  # A release that changed the Action, the MCP server or the benchmarks changes nothing in the
  # plugin but its version number. The directory reviews every version, so that is not one.
  if ! git diff --cached -U0 HEAD | grep -E '^[+-]' | grep -vE '^(\+\+\+|---) ' | grep -qvE '"version": "[0-9.]+"|^. *version: "[0-9.]+"|^.export const VERSION = "[0-9.]+";'; then
    echo "Only the version number differs from the plugin branch: nothing to publish for $v."
    exit 0
  fi
fi
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" commit -q -m "vetcode $v"
git push -q "$remote" plugin
echo "The plugin branch now holds $v."
