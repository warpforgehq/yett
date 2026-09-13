# Contributing

## Build and test

```sh
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Tests that need the `sops` binary print a skip reason when it is not installed.
CI installs a pinned, checksum-verified `sops` on both Ubuntu and macOS, so the
compatibility tests run there.

Keep Rust source files under 400 lines, and leave comments out of code; a file
that outgrows the cap becomes a directory module (`foo.rs` → `foo/mod.rs` plus
topic files).

## Releases

Once the release secrets are configured, push a tag `v<version>` that matches
the version in `Cargo.toml`. `.github/workflows/release.yml` then:

1. builds four native archives on their own runners (`x86_64`/`aarch64` for
   Linux and macOS) and attaches them plus `SHA256SUMS` to the GitHub Release;
2. publishes `@warpforge/yett` and the four platform packages
   `@warpforge/yett-<os>-<arch>` to npm;
3. pushes the Homebrew formula to the tap;
4. publishes the crate to crates.io.

Each publishing job is skipped when its secret is unset:

| Secret | Used for |
| --- | --- |
| `CARGO_REGISTRY_TOKEN` | `cargo publish` |
| `NPM_TOKEN` | npm publishing under `@warpforge` |
| `HOMEBREW_TAP_TOKEN` | pushing `Formula/yett.rb` to the tap |

`HOMEBREW_TAP_REPO` defaults to `warpforgehq/homebrew-tap`. The three shell scripts
the workflow runs can also be run by hand: `scripts/package.sh` builds one
archive, `scripts/gen-npm.sh` materializes the npm tree from the archives, and
`scripts/gen-brew.sh` renders the formula from `SHA256SUMS`.

Archive and package names are versioned; `package.sh` refuses to overwrite an
existing archive, and `gen-npm.sh` stamps the version into every
`package.json`.

## Repository layout

The crate is the repository root, and `.github/workflows/` runs CI and
releases directly. The workflows and scripts assume root-relative paths.

## Manual macOS check

CI cannot mount a RAM disk, so run the `edit` path by hand after changes to
`src/edit/`:

```sh
D=$(mktemp -d) && cd "$D"
yett init --tiers dev --handle your-github-handle   # prompts for the identity passphrase
printf 'hunter2' | yett set --ref DATABASE_PASSWORD dev db/password

cat > editor.sh <<'EOF'
#!/bin/sh
sed -i '' 's/^\( *password:\).*/\1 via-editor/' "$1"
EOF
chmod 755 editor.sh

EDITOR="$PWD/editor.sh" yett edit dev && yett get dev/db/password
EDITOR=vim yett edit dev              # :wq saves; Ctrl-Z suspends the whole job
EDITOR='sleep 300' yett edit dev      # Ctrl-C exits 130 and removes the RAM disk
hdiutil info | grep -c 'ram://'       # expect 0
```

The default identity path uses the passphrase from `keygen`, so `edit`, `get`,
and `run` prompt for it.
