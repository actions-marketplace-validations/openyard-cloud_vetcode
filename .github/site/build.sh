#!/bin/sh
# Builds the site at vetcode.openyard.cloud into <folder>: the page, with the released version
# filled in, and the images it uses. The Pages workflow runs it; nothing else is published.
#
#   sh .github/site/build.sh <folder>
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$1"
v="$(node -p 'require(process.argv[1]).version' "$root/package.json")"
rm -rf "$out"
mkdir -p "$out"
sed "s/{{VERSION}}/$v/g" "$root/site/index.html" > "$out/index.html"
cp "$root/assets/logo.svg" "$root/assets/social-preview.png" "$out/"
printf 'vetcode.openyard.cloud\n' > "$out/CNAME"
if grep -q '{{' "$out/index.html"; then echo "a placeholder was left in index.html" >&2; exit 1; fi
echo "site for vetcode $v in $out"
