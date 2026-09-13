#!/bin/sh
set -eu

version=${1:-}
sums=${2:-}
out=${3:-}

if [ -z "$version" ] || [ -z "$sums" ]; then
  echo "usage: scripts/gen-brew.sh <version> <SHA256SUMS> [output-path]" >&2
  exit 1
fi

if [ ! -f "$sums" ]; then
  echo "SHA256SUMS file not found: $sums" >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
template="$root/packaging/homebrew/yett.rb.tpl"
repo=${YETT_REPO:-warpforgehq/yett}

if [ ! -f "$template" ]; then
  echo "formula template not found: $template" >&2
  exit 1
fi

sha_for() {
  target=$1
  file="yett-v${version}-${target}.tar.gz"
  awk -v f="$file" '$2 == f || $2 == "./" f { print $1; exit }' "$sums"
}

sha_linux_x64=$(sha_for x86_64-unknown-linux-gnu)
sha_linux_arm64=$(sha_for aarch64-unknown-linux-gnu)
sha_darwin_x64=$(sha_for x86_64-apple-darwin)
sha_darwin_arm64=$(sha_for aarch64-apple-darwin)

for entry in \
  "x86_64-unknown-linux-gnu:$sha_linux_x64" \
  "aarch64-unknown-linux-gnu:$sha_linux_arm64" \
  "x86_64-apple-darwin:$sha_darwin_x64" \
  "aarch64-apple-darwin:$sha_darwin_arm64"
do
  if [ -z "${entry#*:}" ]; then
    echo "SHA256SUMS is missing ${entry%%:*}" >&2
    exit 1
  fi
done

rendered=$(
  sed \
    -e "s|__REPO__|$repo|g" \
    -e "s|__VERSION__|$version|g" \
    -e "s|__SHA_LINUX_X64__|$sha_linux_x64|g" \
    -e "s|__SHA_LINUX_ARM64__|$sha_linux_arm64|g" \
    -e "s|__SHA_DARWIN_X64__|$sha_darwin_x64|g" \
    -e "s|__SHA_DARWIN_ARM64__|$sha_darwin_arm64|g" \
    "$template"
)

if [ -n "$out" ]; then
  printf '%s\n' "$rendered" > "$out"
else
  printf '%s\n' "$rendered"
fi
