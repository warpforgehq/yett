# yett — specification

**Status:** draft · **Design record:** [design](adr/0001-design.md)

The name was checked before being written down: `yett` is free on crates.io as of
2026-09-12. The unscoped npm package belongs to a dormant 2022 JS library, so npm
ships under our org scope `@warpforge/yett`, with per-platform binaries beside it.
The first draft called it `envref`, which is an existing Go tool (see Prior art).

## Purpose

Deliver secrets to a process's environment from encrypted files that are safe to
commit, without any plaintext ever reaching disk. One binary, no language
bindings, no server.

The reason it exists as a separate artifact rather than warpforge code: a
project that adopts this must stay runnable by someone who has never installed
warpforge. See "Compatibility guarantees".

## Where the code lives

[github.com/warpforgehq/yett](https://github.com/warpforgehq/yett), published
to crates.io with `publish = true`. It started as a workspace member of the
warpforge repository and was extracted once the interface in this document
stopped moving.

## Non-goals

- **Sandboxing.** Restricting what other processes on the machine can read is
  the host's job, not this tool's. See ADR 0009, invariant 7 for the exact
  claim this tool is allowed to make.
- **A new file format or cipher.** It reads SOPS files and delegates crypto to
  `age`.
- **An audit trail.** No record of who decrypted what.
- **A daemon.** Every invocation is a short-lived process.
- **Secret generation, expiry, or rotation.** It reads and writes values; the
  decision to change one is a human's.
- **Windows.** v1 targets macOS and Linux. The prompt handling, `mlock`, and
  keychain story all differ, and none of our services run there.

## Prior art: why not `envref`

[xcke/envref](https://github.com/xcke/envref) (Go, MIT, active) already does
most of this: `ref://` URIs in a committed `.env`, `envref run -- <cmd>`
injection, seven backends including OS keychain, 1Password, AWS SSM, HashiCorp
Vault and OCI, plus profiles, JSON-schema validation and direnv integration. It
is a good tool and it is further along than we are. Three properties this spec
treats as load-bearing are absent from it, which is the whole reason to build
rather than adopt:

1. **No SOPS format.** Its local vault is SQLite plus age scrypt — its own
   format. So `sops exec-env` cannot read it, the escape hatch does not exist,
   and the SOPS tooling our infra repos already run does not apply. Adopting it
   trades our lock-in for someone else's.
2. **A SQLite blob is not reviewable.** The reason to commit encrypted secrets
   is that a diff shows *which* key changed. A binary blob gives an opaque diff
   and unresolvable merge conflicts — the same objection that rules out
   git-crypt in ADR 0009.
3. **`ENVREF_VAULT_PASSPHRASE`.** It accepts the vault passphrase from an
   environment variable and from config. The passphrase in our design is
   load-bearing precisely because upstream `age` offers no programmatic way to
   supply one, so an agent or a `postinstall` script cannot answer the prompt.
   A passphrase readable from config defeats that.

Minor divergence: its grammar is `ref://<path>` with the backend coming from
config, so one project cannot mix two backends across different variables. This
spec keeps the backend in the URI.

These findings come from its README, not its source. Re-read the code before
acting on any of them.

## Concepts

**Tier** — a named environment (`dev`, `staging`, `prod`). One encrypted file and
one recipient list per tier. Tiers are independent: holding the `dev` key tells
you nothing about `prod`.

**Secret file** — `.yett/secrets.<tier>.enc.yaml`, a plain SOPS file.
Values encrypted, keys in cleartext, so a diff shows which secret changed
without showing what it changed to.

**Access list** — `.yett/secrets-access.yaml`, committed, cleartext. Maps a
person to their age public key per tier. This file is the revocation mechanism:
remove an entry, re-encrypt, and that person cannot read anything committed
afterwards.

**Reference** — a `ref+backend://` URI in a config value, resolved to a secret at
spawn time.

**Identity** — the developer's age private key, stored passphrase-encrypted, and
decrypted only into memory.

## File formats

### Secret file

An ordinary SOPS file. No envelope of ours, no extra metadata. YAML because it
is the intersection of what `sops` and `rops` both read (`rops` has no ENV
format support), and because nesting maps cleanly onto services.

```yaml
db:
    password: ENC[AES256_GCM,data:...,type:str]
stripe:
    api_key: ENC[AES256_GCM,data:...,type:str]
sops:
    age: [...]
    mac: ENC[...]
```

### Access list

```yaml
version: 1
people:
  - handle: ephor                 # GitHub handle, identity for humans only
    keys:
      dev: age1qz8...             # public keys, safe to commit
      staging: age1lm4...
      prod: age1x7v...
  - handle: someone-else
    keys:
      dev: age1p0k...
```

A person with no key for a tier is not a recipient of it. The prod tier
normally has exactly one entry (ADR 0009).

`access sync` regenerates `.sops.yaml` from this file and rewrites the
recipients of every `secrets.<tier>.enc.yaml` whose wrapped key set changed.
`rops` rotates the data key automatically when a key id is removed, so a
removed person cannot decrypt later revisions. That is forward-only: a clone
made before the removal still decrypts, which is why the prod tier rotates the
values at the source as well (ADR 0009, invariant 6). `check` fails when this
file, `.sops.yaml`, and the encrypted files disagree.

`access remove` is the one place a person is dropped. For dev and staging it
edits the list and syncs. For prod it must also state, in its own output, that
every value in the file now needs rotating at its source, and the wording must
say the removed person keeps access to everything already committed — never
"access revoked".

### Generated SOPS config

`.sops.yaml` is generated from the access list, never hand-edited:

```yaml
creation_rules:
  - path_regex: \.yett/secrets\.dev\.enc\.yaml$
    key_groups: [{ age: [age1qz8..., age1p0k...] }]
  - path_regex: \.yett/secrets\.prod\.enc\.yaml$
    key_groups: [{ age: [age1x7v...] }]
```

Generated with a `# generated by yett — edit secrets-access.yaml instead`
header. `yett access sync` rewrites it; `yett check` fails if it is stale,
so CI catches a hand edit.

## Reference grammar

```
ref+<backend>://<path>[?<params>][#<fragment>]
```

Follows the scheme `vals`, helmfile, and the ArgoCD Vault Plugin already use, so
the syntax is not ours to define. The fragment is a JSON-Pointer-style path into
the decrypted document.

```
ref+sops://.yett/secrets.dev.enc.yaml#/db/password
ref+sops://.yett/secrets.prod.enc.yaml#/stripe/api_key
```

`sops` is the only backend at v1. `vault`, `op`, and `awssecrets` are names the
grammar reserves; implementing one must not change any existing config.

A value containing an unresolvable reference is a hard error, never a
passthrough. A literal `ref+sops://...` in an `Authorization` header is either a
dead service or a request sent to a third party with a placeholder in it.

## CLI

```
yett run [--env-file <f>] [--identity <path>] -- <command> [args...]
yett get <tier>/<pointer>             # e.g. `yett get dev/db/url`
yett set [--env-file <f>] [--ref <name>] <tier> <pointer>  # reads value from stdin
yett import [--from <path>] [--tier <t>] [--env-file <path>] [--dry-run] [--exclude <k1,k2>] [--force]
yett edit <tier>                     # $EDITOR on a RAM-backed path
yett init [--tiers <t,...>] [--handle <h>]  # --handle scaffolds one tier end to end
yett keygen [--tier <t>] [--register <h>]   # --register registers the key and refreshes .sops.yaml
yett access list|add|remove|sync
yett check
```

`run` is the whole product; the rest is what makes `run` usable. Every reading
command (`run`, `get`, `check`, `access sync`) takes `--identity <path>`, with
`YETT_IDENTITY` as the environment fallback; see "Key and memory handling".

- **`run`** resolves every reference in the env file (default `.env.refs`),
  merges the result into the current environment, and `exec`s the command. Only
  variables whose value is a reference are touched; everything else in the file
  passes through unchanged. There is no tier flag: a reference names its file,
  and the file name names the tier.
- **`get`** prints one value to stdout. For scripts. Exits non-zero rather than
  printing a partial result. The argument is either a full reference or
  `<tier>/<pointer>`: `yett get dev/db/url` resolves `/db/url` against
  `.yett/secrets.dev.enc.yaml`. The tier always comes from the argument, so a
  command can never read the wrong environment by accident; there is no default
  tier. A missing pointer (`yett get dev`), an empty one (`yett get dev/`), or
  a pointer without a leading segment (`yett get /db/url`) is a usage error.
- **`set`** reads one value from stdin and writes it to the pointer, encrypting
  to the tier's recipients. The pointer may be written as `db/url` or
  `/db/url`; the leading slash is optional. When the tier file does not exist
  it creates it from the recipients in `.yett/secrets-access.yaml`, so the
  first secret needs no separate `sops` step; a tier with no recipients is a
  usage error and creates nothing. With `--ref <name>`, it also upserts the
  canonical reference in `--env-file <f>` (default `.env.refs`), creating that
  file with the `init` header when needed. An existing reference for the name
  is replaced in place; an existing literal value is a usage error checked
  before the encrypted file is changed.
- **`import`** migrates every key from `.env.local` (or `--from <path>`) into
  the selected tier without secret-name heuristics, writes canonical references
  to `.env.refs`, and leaves the source untouched. When the tier already
  exists, imported values are merged into it: existing values are preserved,
  while an imported value overwrites the same key. The configured identity is
  used to open that tier, so an encrypted identity may prompt once. An absent
  tier is created without an identity prompt.
  `--exclude` omits exact key names, `--dry-run` prints the references without
  writing, and `--force` permits replacing literal values in the env file.
- **`init`** creates `.yett/`, `.env.refs`, an empty access list, and the
  generated `.sops.yaml`. With `--handle <h>` and exactly one tier it also
  creates (or reuses) the identity and registers its public key, so the first
  `set` can follow immediately. A tier list with more than one tier plus
  `--handle` is refused, because each tier needs its own identity and prompt.
- **`keygen`** creates the passphrase-encrypted identity at the default path
  and prints the public key. With `--register <h>` it also adds the key to the
  access list for the tier and refreshes `.sops.yaml`. When the identity
  already exists it is unlocked with one prompt and its public key registered
  rather than regenerated. It never rewraps existing encrypted files; that
  stays with `access sync`, run by a current recipient.
- **`edit`** decrypts to a path, runs `$EDITOR`, and re-encrypts on save. The
  path is RAM-backed, never persistent storage: on Linux a tmpfs mount
  (`/dev/shm`), on macOS a small RAM disk created, mounted, and ejected around
  the editor — the approach `pass` ships in `src/platform/darwin.sh`. A real
  path matters because editors rename on save; a `memfd` or an unlinked fd does
  not survive that. If neither backend is available, `edit` fails with a
  message pointing at `set` and `get`. There is no plain `0600`-on-disk
  fallback, unlike `sops edit`.
- **`check`** verifies: `.sops.yaml` matches the access list, every reference in
  the env file resolves, no secret file has a recipient absent from the access
  list. Made for CI.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | usage or config error |
| 2 | decryption failed (wrong passphrase, not a recipient) |
| 3 | a reference did not resolve |
| 4 | access list and `.sops.yaml` disagree |
| — | with `run`, the child's own exit code is propagated verbatim |

## Environment injection

The env file holds references, not values, and is committed:

```
DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url
STRIPE_KEY=ref+sops://.yett/secrets.dev.enc.yaml#/stripe/api_key
LOG_LEVEL=debug
```

Rules:

1. An existing variable in the parent environment wins over the file. This
   matches `dotenv`, `python-dotenv`, `godotenv`, and `dotenvy`, all of which
   defer to an already-set variable, so a project keeps its existing loader and
   gets injected values for free.
2. Resolution happens before `exec`. A failure means the command never starts.
3. No temp file, no `.env` written and deleted, no cache.
4. The child is `exec`'d, not forked-and-waited, so it inherits the terminal and
   signals directly. `run` is transparent.

### Env file grammar

`.env.refs` is line-oriented UTF-8, a strict subset of dotenv so it stays
familiar:

- blank lines, and lines whose first non-space character is `#`, are ignored;
- an optional `export ` prefix is ignored;
- `KEY=VALUE`, with KEY matching `[A-Za-z_][A-Za-z0-9_]*` and whitespace around
  `=` trimmed;
- VALUE runs verbatim to end of line: no quoting, no escapes, no inline
  comments, nothing multiline;
- a repeated KEY is an error, not last-wins;
- a VALUE starting with `ref+` is a reference, anything else is a literal.

## Log redaction

Library-only; the CLI does not filter its child's output, because a wrapper that
mangles arbitrary stdout is worse than one that does not.

```rust
let redactor = Redactor::from_values(&resolved);
let safe = redactor.apply(line);
```

Each resolved value is matched literally, plus its base64 and percent-encoded
forms — a bearer token and a basic-auth header are the two ways a secret
usually appears in a log wearing a disguise. Values shorter than 8 bytes are
skipped: redacting `"true"` would black out half the log.

## Library API

```rust
pub struct Resolver { /* backends, cache */ }

impl Resolver {
    pub fn new() -> Self;
    pub fn resolve(&self, r: &Ref) -> Result<ResolvedSecret>;
    pub fn resolve_env(&self, env: &BTreeMap<String, String>)
        -> Result<BTreeMap<String, ResolvedSecret>>;
}

pub struct AccessList { /* ... */ }
impl AccessList {
    pub fn load(path: &Path) -> Result<Self>;
    pub fn recipients(&self, tier: &str) -> Vec<AgeRecipient>;
    pub fn render_sops_config(&self) -> String;
}

pub struct Redactor { /* ... */ }
```

Values are `SecretString` (`secrecy` crate) everywhere: zeroized on drop, and
`Debug` prints `[REDACTED]` so a stray `{:?}` cannot leak one. What the resolver
hands back is a `ResolvedSecret`: a `SecretString` plus a page lock, so the
returned value stays `mlock`ed and out of core dumps for as long as the caller
holds it, and is wiped when dropped.

## Dependencies

| Crate | Role | Notes |
| --- | --- | --- |
| `age` | crypto, `armor` feature | the `ssh` feature stays off; recipients are native age keys |
| `rops` | SOPS file read/write for age | v0.1.x, one maintainer; the file format is not theirs |
| `secrecy` + `zeroize` | value types, wipe on drop, `Debug` redaction | |
| `clap` | CLI parsing | |
| `serde_yaml` | access list parsing | same YAML crate the daemon uses |

Exact versions are pinned in `Cargo.toml` in the first commit. `rops` is the
risk: the swap costs nothing because the file format is SOPS, and the fallback
is shelling out to the `sops` binary.

## Key and memory handling

**Path.** The identity for tier `<tier>` lives at
`$XDG_CONFIG_HOME/yett/<tier>.key.age` (`~/.config/yett/` when unset). It is
overridden by `--identity <path>`, then by `YETT_IDENTITY`, in that order. The
default path is never a plaintext key; a plaintext identity is accepted only
when one of those two explicitly points at one, which is the CI case.

**Tier selection.** `run` has no tier flag: a reference names its file, and
`secrets.<tier>.enc.yaml` names the tier. A run that touches several tiers
unlocks each tier's identity. `set`, `edit`, `init`, and `keygen` take the
tier as an argument because they act on a file rather than through a reference.

The identity on disk is a passphrase-encrypted age file, which `age` supports
natively (`age-keygen | age -p > key.age`). The passphrase is prompted on a TTY
and cannot come from the environment, so nothing can answer for the developer.

In memory: `zeroize` on drop, `mlock` the pages, `madvise(MADV_DONTDUMP)`,
`RLIMIT_CORE=0`, and `memfd_secret` where the kernel offers it. Two honest
limits: `mlock` is page-granular so unrelated secrets can share a page, and
`MADV_DONTDUMP` is advisory.

Decryption path: `rops` in-process for age. `rops` 0.1.7 has no API for an
identity argument, so the decrypted identity is passed through `ROPS_AGE`,
inside a single bridge module that serializes access with a process-wide lock,
restores the variable afterwards, and pins `ROPS_AGE_KEY_FILE` to a path that
does not exist so `rops` cannot silently add identities from its own config
directory. `/proc/<pid>/environ` shows the exec-time environment, so a runtime
`set_var` is not visible there, and `yett run` builds the child's environment
from a snapshot taken before any identity is loaded. Shelling out to the `sops`
binary (needed for GCP KMS, Azure Key Vault, PGP) has to pass the key through
`SOPS_AGE_KEY`, putting it in a subprocess environment — a weaker guarantee, and
the reason `rops` stays primary rather than interchangeable.

## Compatibility guarantees

These are tested, not documented:

1. A file written by `yett` is readable by the `sops` binary, and the reverse.
2. `sops exec-env .yett/secrets.dev.enc.yaml -- <cmd>` produces the same
   environment as `yett run -- <cmd>`. CI diffs the two.

Tests generate an ephemeral age key and identity in a temp directory; no key
material is committed. A test that needs the `sops` binary skips with a printed
reason when it is absent, and CI installs `sops`. The env comparison runs both
commands with `printenv`, sorts the output, and diffs.

Guarantee 2 is the point of the whole design. If it breaks, a project has become
dependent on us, and nobody would notice from reading the code.

## Distribution

GitHub Releases with per-platform archives is the base every other channel
wraps, and what CI and `curl | sh` need. On top: a brew tap as the primary path
(`warpforgehq/homebrew-tap`), and npm as
`@warpforge/yett`, shipping the binary through per-platform
`@warpforge/yett-<os>-<arch>` optionalDependencies the way esbuild and biome do.
`cargo install` comes free. No PyPI, no Go module — a
Python service runs `yett run -- python app.py`, the same as any other, and
nobody imports this code.

There are no open questions: everything an implementer would otherwise have to
invent is decided above.
