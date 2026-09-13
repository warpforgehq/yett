#!/bin/sh
set -eu

version=${1:-}
artifacts=${2:-}

if [ -z "$version" ] || [ -z "$artifacts" ]; then
  echo "usage: scripts/gen-npm.sh <version> <artifacts-dir>" >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
template="$root/packaging/npm"
out="${artifacts%/}/npm"

rm -rf "$out"
mkdir -p "$out"
cp -R "$template/." "$out/"

extract_binary() {
  target=$1
  pkgdir=$2
  archive="${artifacts%/}/yett-v${version}-${target}.tar.gz"
  if [ ! -f "$archive" ]; then
    echo "missing release archive: $archive" >&2
    exit 1
  fi

  tmp=$(mktemp -d)
  tar -xzf "$archive" -C "$tmp"
  binary="$tmp/yett-v${version}-${target}/yett"
  if [ ! -f "$binary" ]; then
    rm -rf "$tmp"
    echo "archive $archive does not contain yett-v${version}-${target}/yett" >&2
    exit 1
  fi

  mkdir -p "$out/$pkgdir/bin"
  cp "$binary" "$out/$pkgdir/bin/yett"
  chmod 755 "$out/$pkgdir/bin/yett"
  rm -rf "$tmp"
}

extract_binary x86_64-unknown-linux-gnu yett-linux-x64
extract_binary aarch64-unknown-linux-gnu yett-linux-arm64
extract_binary x86_64-apple-darwin yett-darwin-x64
extract_binary aarch64-apple-darwin yett-darwin-arm64

for pkgjson in "$out"/*/package.json; do
  sed "s/0\\.0\\.0/$version/g" "$pkgjson" > "$pkgjson.tmp"
  mv "$pkgjson.tmp" "$pkgjson"
done

printf '%s\n' "$out"
