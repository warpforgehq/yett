#!/bin/sh
set -eu

version=${1:-}
target=${2:-}

if [ -z "$version" ] || [ -z "$target" ]; then
  echo "usage: scripts/package.sh <version> <target>" >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

target_dir=${CARGO_TARGET_DIR:-target}

find_binary() {
  if [ -f "$target_dir/$target/release/yett" ]; then
    printf '%s\n' "$target_dir/$target/release/yett"
    return 0
  fi
  host=$(rustc -vV | sed -n 's/^host: //p')
  if [ "$host" = "$target" ] && [ -f "$target_dir/release/yett" ]; then
    printf '%s\n' "$target_dir/release/yett"
    return 0
  fi
  return 1
}

binary=$(find_binary || true)
if [ -z "$binary" ]; then
  echo "no prebuilt binary for $target; running cargo build --release --locked" >&2
  cargo build --release --locked --target "$target"
  binary=$(find_binary || true)
fi

if [ -z "$binary" ]; then
  echo "expected binary $target_dir/$target/release/yett is missing" >&2
  exit 1
fi

if [ ! -f README.md ]; then
  echo "README.md is missing; run from the yett repository root" >&2
  exit 1
fi

name="yett-v${version}-${target}"
archive="${name}.tar.gz"
if [ -e "$archive" ]; then
  echo "$archive already exists; remove it or pick another version" >&2
  exit 1
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

mkdir -p "$stage/$name"
cp "$binary" "$stage/$name/yett"
chmod 755 "$stage/$name/yett"
cp README.md "$stage/$name/README.md"

tar -czf "$archive" -C "$stage" "$name"

if command -v sha256sum >/dev/null 2>&1; then
  sha=$(sha256sum "$archive" | cut -d ' ' -f1)
else
  sha=$(shasum -a 256 "$archive" | cut -d ' ' -f1)
fi

printf '%s  %s\n' "$sha" "$archive"
