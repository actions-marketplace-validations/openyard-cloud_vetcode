#!/bin/sh
# Builds the folder that is published as the Claude Code plugin: the manifest, the skill, the
# hooks, and a README written for the plugin's listing. Nothing else from this repository
# (benchmarks, tests, the GitHub Action, the MCP server) is part of the plugin.
#
#   sh .github/plugin/build.sh <folder>            build it
#   sh .github/plugin/build.sh <folder> <remote>   build it, then commit it to the remote's
#                                                  `plugin` branch, once per version
#
# The Release workflow runs the second form. The Claude plugin directory follows that branch,
# so what it scans and what people install is exactly this folder.
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$1"
remote="${2:-}"

rm -rf "$out"
mkdir -p "$out/.claude-plugin"
cp "$root/.claude-plugin/plugin.json" "$root/.claude-plugin/icon.png" "$out/.claude-plugin/"
cp -R "$root/skills" "$root/hooks" "$out/"
cp "$root/LICENSE" "$root/PRIVACY.md" "$root/SECURITY.md" "$out/"
cp "$root/.github/plugin/README.md" "$out/README.md"
find "$out" -name .DS_Store -delete

[ -n "$remote" ] || exit 0

version() { node -p 'JSON.parse(require("fs").readFileSync(0, "utf8")).version'; }
v="$(version < "$out/.claude-plugin/plugin.json")"
cd "$out"
git init -q -b plugin
if git fetch -q --depth 1 "$remote" plugin 2>/dev/null; then
  if [ "$(git show FETCH_HEAD:.claude-plugin/plugin.json | version)" = "$v" ]; then
    echo "The plugin branch already holds $v."
    exit 0
  fi
  git reset -q --soft FETCH_HEAD
fi
git add -A
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" commit -q -m "vetcode $v"
git push -q "$remote" plugin
echo "The plugin branch now holds $v."
