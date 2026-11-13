#!/bin/sh
# Builds the Gemini CLI extension into <folder>: the extension itself in <folder>/vetcode, and the
# release assets Gemini CLI downloads, darwin.vetcode.tar.gz, linux.vetcode.tar.gz and
# win32.vetcode.zip (the same files three times: Gemini picks an asset by the name's platform, and
# without one it would install the repository itself, whose hooks/hooks.json is Claude Code's).
#
#   sh .github/gemini/build.sh <folder>
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$1"
ext="$out/vetcode"
rm -rf "$out"
mkdir -p "$ext/hooks" "$ext/mcp"
cp "$root/gemini-extension.json" "$root/package.json" "$root/LICENSE" "$root/PRIVACY.md" "$root/SECURITY.md" "$root/README.md" "$ext/"
cp "$root/.github/gemini/hooks.json" "$ext/hooks/hooks.json"
cp "$root/mcp/server.mjs" "$ext/mcp/"
cp -R "$root/skills" "$ext/"
find "$ext" -name .DS_Store -delete
(cd "$ext" && tar -czf "$out/linux.vetcode.tar.gz" . && cp "$out/linux.vetcode.tar.gz" "$out/darwin.vetcode.tar.gz" && zip -qr "$out/win32.vetcode.zip" .)
echo "Gemini CLI extension $(node -p 'require(process.argv[1]).version' "$ext/gemini-extension.json") in $out"
