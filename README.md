# yett

Keep your project's secrets in Git. Values are encrypted, a diff shows which
key changed, and the decrypted values go into a process's environment when you
run it, never into a file yett writes.

**Status:** pre-1.0. The interface is still settling. macOS and Linux.

## The problem

The most sensitive part of a project's configuration is usually the only part
that is not versioned. Four things follow from that.

- **Env drift.** Everyone keeps a private `.env.local`. The files diverge, and
  nobody notices until a service behaves differently for one developer.
- **No history.** There is no diff and no review for a connection string, so
  nobody can say who changed it, when, or to what.
- **Whole-file encryption breaks review.** git-crypt and similar tools turn the
  file into an opaque blob. A diff shows that something changed, never which
  value, and merge conflicts stop being resolvable.
- **A `0600` file stops nothing running as you.** The coding agents you spawn,
  an npm `postinstall`, any dependency in the tree runs as your user and can
  read it.

## What yett does

Values live in `.yett/secrets.<tier>.enc.yaml`, an ordinary
[SOPS](https://github.com/getsops/sops) file encrypted to
[age](https://github.com/FiloSottile/age) recipients. Keys stay in cleartext
and values are encrypted, so a diff shows which secret changed without showing
what it changed to. A committed `.env.refs` holds references instead of values:

```
DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url
DATABASE_PASSWORD=ref+sops://.yett/secrets.dev.enc.yaml#/db/password
LOG_LEVEL=debug
```

`yett run -- <cmd>` resolves every reference in memory and `exec`s the command
with the results in its environment. No temp file, no `.env` written and
deleted, no cache. Resolution happens before `exec`, so a failed reference
means the command never starts. Because the child is `exec`'d rather than
forked, the terminal, signals, and exit code pass through unchanged.

A variable already set in the parent environment wins over the file, matching
`dotenv`, `python-dotenv`, `godotenv`, and `dotenvy`, so a project keeps its
existing loader. Only values starting with `ref+` are touched; everything else
in the file passes through as a literal.

There is no daemon and no file format of ours. Every invocation is a
short-lived process, and the files are plain SOPS.

## Install

```sh
brew install warpforgehq/tap/yett   # macOS and Linux
cargo install yett                  # with a Rust toolchain
npm install -g @warpforge/yett      # or run it once with `npx yett`
```

Every GitHub Release carries prebuilt archives for macOS and Linux on arm64 and
amd64. The npm package selects the right binary through per-platform
`@warpforge/yett-<os>-<arch>` optional dependencies, so `npx yett` needs no
compiler.

The `sops` binary is optional. Everything below runs through `yett` alone;
`sops` stays useful for reading and editing the files without it.

## Quick start

Scaffold the project, create a passphrase-encrypted identity, and register its
public key in one command:

```console
$ yett init --tiers dev --handle your-github-handle
yett: passphrase for the dev identity:
yett: confirm the dev passphrase:
created ./.yett/secrets-access.yaml
created ./.sops.yaml
created ./.env.refs
registered your-github-handle for dev
public key: age1qz8...
if encrypted files for dev already exist, a current recipient must run `yett access sync`
```

`--handle` takes exactly one tier, because each tier needs its own identity and
its own prompt. For a second tier, run `yett keygen --register your-github-handle --tier staging`.
Plain `yett init` (no `--handle`) writes the same files and stops there, which is
the path for scripts and CI.

Write the first secret. `set` creates the encrypted file, encrypting to the
recipients in the access list; the value comes from stdin:

```console
$ printf 'correct-horse-battery-staple' | yett set dev DATABASE_PASSWORD

$ yett get dev/DATABASE_PASSWORD
yett: passphrase for the dev identity:
correct-horse-battery-staple
```

Add the reference to `.env.refs` (the file `init` created, with a commented
example):

```
DATABASE_PASSWORD=ref+sops://.yett/secrets.dev.enc.yaml#/DATABASE_PASSWORD
LOG_LEVEL=debug
```

Run a command with the resolved environment:

```console
$ yett run -- sh -c 'echo "password=$DATABASE_PASSWORD log=$LOG_LEVEL"'
yett: passphrase for the dev identity:
password=correct-horse-battery-staple log=debug
```

Commit `.env.refs`, `.yett/secrets.dev.enc.yaml`, `.yett/secrets-access.yaml`,
and `.sops.yaml`. The identity stays in `~/.config/yett/` and is never
committed.

## Day-to-day

```console
$ printf 'new-value' | yett set dev db/password     # replace one value
$ yett get dev/db/password
$ yett edit dev                                      # $EDITOR on a RAM-backed copy
$ yett check                                         # CI: does everything agree?
```

`yett set` on a file that does not exist yet creates it, so a new tier or a new
key never needs a separate encryption step. `edit` opens the decrypted document
in `$EDITOR` and re-encrypts on save; the file it hands the editor is
RAM-backed (Linux `/dev/shm`, a macOS RAM disk created and ejected around the
editor), never a plain file on disk.

### Working as a team

Step-by-step instructions for every teammate, including who runs `sync` and
what to push: [TEAM.md](TEAM.md).

Each developer generates their own identity and registers its public key:

```console
$ yett keygen --register teammate --tier dev
```

That writes `.yett/secrets-access.yaml` and refreshes `.sops.yaml`. Commit the
list; when encrypted files already exist, a current recipient runs `yett access
sync` to rewrap them so the new key can decrypt them. `access sync` regenerates
`.sops.yaml` from the list and rewraps every tier whose recipient set changed.
Adding a recipient shares future changes; it does not hand over history, because
a clone made before the change still holds what it held.

Removing someone works the same way in reverse. They lose access to everything
committed after the change, and keep whatever their clone already has. For the
prod tier, removal means rotating every value at its source as well; the
command says so in its output.

### CI

```console
$ yett check --identity "$CI_IDENTITY" ; echo $?
0
```

`check` fails when the access list, `.sops.yaml`, and the encrypted files
disagree, and when any reference in `.env.refs` does not resolve. Point
`--identity` at a plaintext key file exported from CI secrets for unattended
runs; the default identity path only accepts a passphrase-encrypted key.

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | usage or config error |
| 2 | decryption failed (wrong passphrase, not a recipient) |
| 3 | a reference did not resolve |
| 4 | the access list, `.sops.yaml`, and the files disagree |
| — | with `run`, the child's own exit code is propagated verbatim |

## Commands

| Command | What it does |
| --- | --- |
| `yett init [--tiers <t,...>] [--handle <h>]` | scaffold `.yett/`, `.env.refs`, the access list, and `.sops.yaml`; with `--handle`, also create and register the identity |
| `yett keygen [--tier <t>] [--register <h>]` | create the passphrase-encrypted identity; with `--register`, also add its public key to the access list |
| `yett run [--env-file <f>] -- <cmd>` | resolve `.env.refs` and `exec` the command |
| `yett get <tier>/<pointer>` | print one value to stdout, for scripts; a full `ref+sops://...` also works |
| `yett set <tier> <pointer>` | replace one value, or create the file, reading the value from stdin |
| `yett edit <tier>` | `$EDITOR` on a RAM-backed copy of the document |
| `yett access list\|add\|remove\|sync` | manage `.yett/secrets-access.yaml` and `.sops.yaml` |
| `yett check` | verify the access list, `.sops.yaml`, and every reference |

`init` refuses to overwrite existing project files. With `--handle` it requires
one tier and a terminal, then runs the same registration as `keygen --register`
so the first `set` can follow immediately; if the prompt is interrupted, the
project files stay and the printed line resumes setup.

`keygen` writes the passphrase-encrypted identity to
`$XDG_CONFIG_HOME/yett/<tier>.key.age` (`~/.config/yett/` when unset), or
reuses the existing file by unlocking it, and prints the public key.
`--register <handle>` adds that key to `.yett/secrets-access.yaml` for the tier
and refreshes `.sops.yaml`; it never rewraps encrypted files, so when those
already exist a current recipient runs `access sync`.

`access` treats `.yett/secrets-access.yaml` as the source of truth. `list`,
`add`, and `remove` edit it; `sync` regenerates `.sops.yaml` from it and rewraps
the tiers whose recipient set changed. For the prod tier, `remove` quotes the
forward-only rule in its output and requires `--force-prod`.

Every reading command takes `--identity <path>`, with `YETT_IDENTITY` as the
environment fallback. Otherwise the identity for tier `<tier>` is read from the
default path above, where it must be passphrase-encrypted. A plaintext key is
accepted only when `--identity` or `YETT_IDENTITY` points at one explicitly.

### References

A reference is `ref+<backend>://<path>[?<params>][#<fragment>]`. The fragment
is a JSON Pointer into the decrypted document, so `#/db/password` reaches a
nested value. `sops` is the only implemented backend; `vault`, `op`, and
`awssecrets` parse and report that the backend is not implemented.

An unresolvable reference is a hard error, never a passthrough. A literal
`ref+sops://...` in an `Authorization` header is either a dead service or a
request sent to a third party with a placeholder in it.

## Using it in a monorepo

`init`, `access`, `set`, `edit`, and `check` work on the `.yett/` directory and
`.sops.yaml` at the current working directory. `run` and `get` ignore the
layout and follow the path inside the reference, resolved relative to the
working directory.

For a monorepo, keep one `.yett/` and one `.sops.yaml` at the repository root,
and let each app's references point at it (`ref+sops://../../.yett/...` when
the command runs from the app directory). A per-app `.yett/` also works and
never conflicts, but it means one access list and one generated `.sops.yaml`
per app. `yett` does not walk up the tree looking for `.yett/` yet.

## Leaving: compatibility with sops

These guarantees are tested in `tests/sops_compat.rs`, which runs in CI on
Ubuntu and macOS.

- A file written by `yett` decrypts with `sops --decrypt`.
- A file encrypted by `sops --encrypt --age <recipient>` resolves through
  `yett get`.
- For a flat document whose keys are environment variable names,
  `sops exec-env <file> <cmd>` and `yett run -- <cmd>` produce the same values.
  The test runs `printenv` under both, sorts, and diffs.

The env comparison only works for flat documents. `sops exec-env` refuses a
nested one because it renders the document as dotenv first. `sops --decrypt`
reads nested documents fine, and so does `yett`; running a nested project
without `yett` means mapping the values into the environment yourself.

If you stop using `yett`, no file needs migrating. The identity is the only
thing that stays behind, and any age-compatible tool can use it.

## Security scope

Secrets arrive as environment variables. A process running as you can read
another process's environment. This does not defend against code running as
you.

The protections are narrower. Encrypted files are safe to commit, yett never
writes a resolved value to a file, and the identity at the default path is
passphrase-encrypted. yett reads the passphrase only from the terminal: there
is no environment-variable or config-file channel for it. Each
command is a new process, so it prompts once per tier it touches; nothing stays
unlocked between commands. In memory, secret buffers are zeroized on drop and,
where the platform allows,
locked and excluded from core dumps; the spec and ADR list the limits of that,
including the fact that `mlock` is page-granular and the protection is
best-effort.

Removing someone from the access list is forward-only. They cannot decrypt
anything committed afterwards, and they keep whatever their clone already
holds. No rotation reaches back into git history. For the prod tier the values
must be rotated at their source, and `yett access remove` says so.

## Name

*yett* is the Scots word for a gate, pronounced /jɛt/, like English "yet". In
Scottish castles and tower houses a yett was the hinged gate of interlaced iron
bars, set behind the wooden door: if the door burned, the yett still held. The
root is Old English *ġeat*, the same as "gate".

## Project

The crate lives at [github.com/warpforgehq/yett](https://github.com/warpforgehq/yett).
See [CONTRIBUTING.md](CONTRIBUTING.md) for the build, test, and release
process.
