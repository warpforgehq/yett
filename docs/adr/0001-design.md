<!-- Snapshot of warpforge ADR 0009 (2026-09-01). Path references such as
     `crates/yett` and `src/...` point at the warpforge repository. -->

# 0009 — Service secrets are SOPS files warpforge reads, not a warpforge format

**Status:** proposed (2026-09-01)

## Context

The problem is env drift, not secret storage. Every developer on a team keeps
their own `.env.local`, they diverge, and the divergence is invisible until
someone's service behaves differently from everyone else's. The most sensitive
part of a project's configuration is also the only part that is not versioned,
so there is no history of who changed a connection string and to what.
Committing encrypted secrets puts that file back under review and makes a fresh
checkout runnable.

Warpforge spawns every service itself (`src/service/spawn.rs`) and builds its
environment, so a secret can go from ciphertext to a child process's env without
ever being written to disk. No `.env.local`, no "download this from 1Password
and drop it next to the config", nothing to commit by accident. That, not the
encryption, is the part warpforge is placed to do.

The substitution machinery exists. `ports::interpolate_env`
(`src/ports/mod.rs:117`) already rewrites `${db.port}` in env values, and
reference resolution rides the same pass.

Two constraints shape the decision, and both come from outside the daemon:

**Backends are polyglot and warpforge is not their only client.** Services are
Node, Python, Go, and Rust. A developer without warpforge installed must be able
to run the same project with the same secrets. If the answer is "install
warpforge", the feature is a lock-in.

**We already pay for SOPS elsewhere.** Our infra repos use SOPS on Kubernetes
and the SRE team ended up writing a tool to manage it. That cost is real and
should not be paid twice.

Scope, decided rather than derived: the thing being protected is the values that
used to sit in `.env` files. Protecting the repository is not a goal, and
neither is an audit trail of who read which value.

The one attacker worth designing against is code running as the developer's own
user: the coding agents warpforge spawns, an npm `postinstall`, a dependency
nobody read. That is not a hypothetical for this product, it is a feature of it.
A fully compromised machine, where something can drive the keychain prompt or
read the daemon's memory, stays out of scope.

## Decisions

**Warpforge defines no file format and no cipher.** It reads SOPS files under
`.yett/`, encrypted to age recipients, with `.sops.yaml` `creation_rules`
deciding who can decrypt what. SOPS encrypts values and leaves
keys in plaintext, so diffs stay reviewable, and it is a CNCF Sandbox project
with a stable file format rather than something we would have to keep alive.

**Three tiers, three files, three recipient lists.** `secrets.dev.enc.yaml`,
`secrets.staging.enc.yaml`, `secrets.prod.enc.yaml`, matched by `path_regex` in
`.sops.yaml` `creation_rules` so each tier has its own recipients. Most of the
team is a recipient of dev only.

**Recipients are dedicated age keys, one per developer per tier.** Not
SSH-derived. A developer has one SSH key, so an SSH-based recipient is one
identity, and a stolen copy of it opens every tier the developer can read.

**The prod tier has one recipient**, the project owner. Not the team. That makes
invariant 6's rotation duty cheap, because removing the only prod recipient
means the project is changing hands and its credentials were going to be rotated
anyway.

**A private key never exists as a plaintext file.** The identity on disk is a
passphrase-encrypted age file, which `age` supports natively: `age-keygen |
age -p > prod.key.age`, and `-i` accepts that file and asks for the passphrase.
The daemon asks once per session and keeps the decrypted identity in memory
only.

The threat this answers is not a stolen laptop. It is every process running as
the same user: the coding agents warpforge itself spawns, an npm `postinstall`
script, any dependency in the tree. A `0600` file stops none of them. An
encrypted one hands them ciphertext, and upstream `age` has no way to supply a
passphrase from the environment, so nothing can answer the prompt on the
developer's behalf.

The macOS keychain is a convenience on top of this, not the mechanism: Touch ID
instead of typing. Choosing the passphrase as the actual control is what keeps
the two platforms on one code path, because the Linux secret service cannot
provide the property we want at all. gnome-keyring deliberately has no
per-application access control, and the project calls adding one "security
theater": any process running as the user reads any unlocked secret with no
prompt, and the login keyring unlocks at login. It would be a dependency bought
for nothing.

One honest gap: `rops` 0.1.7 exposes no way to hand it an identity — it reads
`ROPS_AGE` from the process environment. On the in-process path we decrypt the
identity with the `age` crate ourselves and set that variable only around the
call, inside one module that holds a process-wide lock and restores the previous
value; `/proc/<pid>/environ` reflects the exec-time environment, not runtime
changes, and `yett run` builds the child's environment from a snapshot taken
before any identity is loaded. It is still weaker than passing bytes, which is
why this is pinned to `rops`: revisit if the crate exposes explicit keys, and
before the library is embedded in a multi-threaded host. The `sops` shell-out
has to pass the key through `SOPS_AGE_KEY`, which puts the key in a subprocess
environment that the same user can read from `/proc`. That is a weaker guarantee
on the fallback path, and a reason to keep `rops` primary rather than
interchangeable.

`.yett/secrets-access.yaml` maps a GitHub handle to that developer's public
key per tier, and warpforge writes the recipients into `.sops.yaml` from it.
Onboarding is `age-keygen` plus a PR adding the public key, which warpforge's UI
generates. The file needs a CODEOWNERS entry, and who owns it is the project
owner's call, per project.

That review is what makes the list worth trusting, and its ceiling is worth
stating: a GitHub org admin can bypass CODEOWNERS, so the list is exactly as
trustworthy as the org's admin set. Warpforge cannot improve on that and should
not pretend to.

Removing a handle and running `sops updatekeys` drops their wrapped data key, so
they cannot decrypt anything committed after that point. This is how our infra
repos already revoke access, and the list is a line in a PR diff. Its one limit
is invariant 6.

**Hardware-backed keys are out of scope.** `age` cannot talk to a security
token, so an `sk-ssh-ed25519@openssh.com` key is skipped rather than used, and
there is no FIDO recipient type. A recipient must hold a software key. If the
team ever mandates token-resident keys, this ADR needs replacing, not patching.

**The escape hatch is an invariant, not a courtesy.** This must produce the same
environment warpforge produces, with no warpforge on the machine:

```bash
sops exec-env .yett/secrets.dev.enc.yaml -- npm run dev
```

`sops exec-env` decrypts into a child process's environment and writes no
plaintext file, which is exactly what the daemon does. A CI check runs the two
paths and compares the resulting env.

**A secret reference is a backend URI, not a file path.** The config
value is `ref+sops://.yett/secrets.dev.enc.yaml#/db/password`, following the
`ref+backend://path#/fragment` scheme that helmfile, `vals`, and the ArgoCD
Vault Plugin already use. Adding `ref+vault://`, `ref+op://`, or
`ref+awssecrets://` later changes the daemon, not any project's
`workspace.yaml`.

**Decryption is in-process for age, shelled out for everything else.** The
`rops` crate is SOPS in Rust and covers age and AWS KMS; anything else
(GCP KMS, Azure Key Vault, PGP) shells out to the `sops` binary. mise ships
this exact split, with `rops` as the default path and the CLI behind a flag.
Cargo has no cryptographic dependency today, and this adds one crate rather
than a hand-rolled scheme.

Native age recipients are also what keeps `rops` usable. Its lib crate declares
`age = { features = ["armor"] }` with the `ssh` feature off, so it cannot handle
`ssh-ed25519` recipients at all. Choosing dedicated age keys means we never need
that feature, and no upstream patch is on the critical path.

**Service secrets stop at the service.** Agent PTYs
(`src/agent.rs:135`, the only `CommandBuilder` in the tree) do not receive them.
See invariant 1.

**Known secret values are redacted on the way into the log buffer.**
`ManagedService::push_log` (`src/service/mod.rs:104`) is the single choke point for
every line the UI renders and `read_service_logs` returns.

**What we build on, layer by layer.** The bottom two layers are other people's
and replaceable; the rest does not exist in Rust today.

| Layer | Owner |
| --- | --- |
| crypto | `age` crate |
| SOPS file read/write | `rops` crate, `sops` binary for other key services |
| `ref+backend://` resolver | ours |
| env injection into the child process | ours |
| log redaction | ours |
| `secrets-access.yaml` to `.sops.yaml` | ours |
| CLI | ours |

`rops` states full SOPS file-format compatibility in both directions as a goal
and explicitly does not aim for CLI parity, which is the half we want. It reads
YAML, JSON, and TOML but not ENV, so **the secrets file is YAML** — the
intersection with what `sops` supports. Its key services are age and AWS KMS.

`rops` is v0.1.x with one maintainer, which is a real dependency risk on
security-adjacent code. It is accepted because the swap costs nothing: the file
format is not theirs, so replacing `rops` with a `sops` shell-out migrates no
files. Same argument as the escape hatch, pointed inward.

**Existing dotenv code keeps working, and that is a constraint, not a hope.**
The supported languages are Node, Python, Go, and Rust; anything else is out of
scope. There is no per-language work, because every one of those ecosystems ships
a loader that defers to an already-set environment variable, and puts the
opposite behaviour behind an explicit opt-in:

| Language | Loader | Defers to existing env | Inverts with |
| --- | --- | --- | --- |
| Node | `dotenv` | yes | `config({ override: true })` |
| Python | `python-dotenv` | yes | `load_dotenv(override=True)` |
| Go | `joho/godotenv` | `Load()` | `Overload()` |
| Rust | `dotenvy` | `dotenv()` | `dotenv_override()` |

So warpforge injects the value, the app's own loader finds it already present
and leaves it alone, and a missing `.env` file makes the loader a no-op. Vite
gives process-environment variables the highest priority for the same reason,
and `vite.config.ts` sees only `process.env` during evaluation, which is exactly
what we inject.

Three known breakages, each a project's own choice to fix: the `override`
variant of any loader inverts the precedence and lets the file beat us; `VITE_*`
values are inlined into the client bundle at build time and are therefore public
whatever we do; and code that throws on a missing `.env` needs that check
removed.

**Distribution is a binary, not a package per language.** The CLI is a static
binary nobody imports, so a language registry buys nothing: a Python service
runs `<cli> run -- python app.py`, the same way a Node one does. GitHub Releases
with prebuilt per-platform archives is the base every other channel wraps, and
the one that CI and `curl | sh` need. On top of it, a brew tap as the primary
path and npm as a convenience for Node projects, shipping the binary through
per-platform `optionalDependencies` the way esbuild and biome do. `cargo install`
comes free with Rust and stays the slow third option. No PyPI, no Go module.

Nothing breaks for a developer who refuses to install anything of ours: the
files are plain SOPS, so `brew install sops` reads them. Our CLI is a
convenience on top of a tool we did not write, which is the whole point.

**Where the code lives.** The resolver, the env injector, the log redactor, and
the access-list handling are useful outside warpforge, and no Rust equivalent of
`vals` exists. They start as `crates/yett`, a workspace member of this
repository with `publish = true`, so the existing workspace tooling covers them,
and move to their own repository once the interface stops moving. Publishing the
crate under the warpforge org, with the CLI above, gives the escape hatch a
second implementation instead of one. The artifact is specified in
[`docs/specs/yett.md`](../specs/yett.md). Two conditions: the crate defines no
file format and no cipher, delegating to `age` and the SOPS format, and we
accept ownership of security issue reports under the org's name.

**The library's claim is narrow, and the process boundary is warpforge's.** What
the library promises: secrets are encrypted at rest, and no plaintext is written
to disk. Nothing about defending a developer from code executing as that
developer. Sandboxing the spawn — Landlock or Seatbelt on the identity path, a
PID namespace so an agent cannot read another process's `/proc`, an egress
allowlist so a value that leaked cannot leave — is a warpforge feature and gets
its own record, not yet written.

The split is also where the product value sits. The library is a commodity we
can give away; applying a sandbox at spawn is available only to whoever owns the
spawn path, and warpforge owns it for both services and agents. It also needs no
configuration, no opt-in, and no user-facing documentation: a developer gets it
by running the agent through warpforge. That asymmetry is the reason to keep the
two layers apart rather than folding the sandbox into the crate.

**The warpforge side is not written yet, and it is tracked separately.** Three
seams already exist, so the integration needs no new architecture:
`src/service/spawn.rs:173-189` builds the service env (resolution goes in after
port interpolation, and an unresolved reference must fail the service the same
way a surviving `${svc.port}` does); `ManagedService::push_log`
(`src/service/mod.rs:104`) is the single writer into the service log buffer
(redaction goes there, not at call sites); `src/agent.rs:135` is the only agent
PTY spawn site (the regression test that a resolved service secret never reaches
an agent env belongs next to it). Until that work lands, a project can set
`command: yett run -- <cmd>` in its workspace config, but the identity must be
supplied non-interactively — daemon-spawned services have no TTY — which means
the CI-grade plaintext `--identity` path, not the passphrase path. The safe
experience (unlock once per session, log redaction) is the daemon's job, and
those three items are recorded in the backlog.

**Naming:** a config value carries a `ref+sops://` URI, "secret provider" in code,
and the standalone crate and CLI are `yett`
([spec](../specs/yett.md)). Not `vault` — `src/daemon/accounts/` already uses that
word for agent account credentials, and two meanings will be indistinguishable in
conversation within a month.

## Rejected alternatives

- **A central store** (OpenBao, Infisical, Vault, Doppler). Rejected outright,
  not deferred: we are not making the ability to start a dev environment depend
  on someone else's product being up, licensed, and authenticated against. It
  would buy rotation without touching the repo, TTL'd credentials, and an audit
  trail we have decided we do not need. The `ref+backend://` scheme still leaves
  the door open, but as an extension point for whoever wants it, not as a plan
  of ours. What replaces it here is scope: the prod tier has one recipient, so
  the blast radius the central store would have shrunk is already small.
- **dotenvx.** The best polyglot ergonomics of the lot: `dotenvx run -- cmd`
  works in every language, and there are Rust and Node bindings. Against it:
  flat `.env` only, a secp256k1/ECIES scheme with a much smaller review surface
  than age, and `.env.keys` living in the project directory, which is a bad
  shape in a tool that also runs coding agents over that directory.
- **A warpforge-native encrypted store.** Fails the escape-hatch test on the
  first day and makes us the maintainer of a file format.
- **The OS keychain as the security boundary** (`keyring` crate over macOS
  Keychain, Windows Credential Manager, and freedesktop secret-service). The
  cross-platform API exists; the guarantee does not. Linux secret-service has no
  per-application access control by design, so it protects against another user
  and against an attacker while you are logged out, but not against code running
  as you, which is the only attacker we care about. Keeping it as the boundary
  would mean one story on macOS and a placebo on Linux.
- **git-crypt / transcrypt.** Whole-file encryption turns secrets into binary
  blobs, so the diff is useless and review cannot see which value changed.
- **Adopting `xcke/envref`** (Go, MIT, active), which already ships reference
  resolution, `run --` injection and seven backends. Rejected for three
  reasons, each fatal to a decision above: its store is SQLite plus age scrypt
  rather than SOPS, so the escape hatch cannot exist; a SQLite blob has the same
  unreviewable diff as git-crypt; and it accepts the vault passphrase from an
  environment variable and from config, which is exactly the property this
  design relies on `age` *not* having. Reasoning is recorded in
  [`docs/specs/yett.md`](../specs/yett.md).
- **Building our own SOPS management layer.** The SRE tool exists because SOPS
  across many infra repos means coordinating recipients and rotations at scale.
  Warpforge's scope is one repo and three recipient lists, so the UI is three
  operations over `sops updatekeys`: add recipient, remove recipient,
  re-encrypt. If it grows past that, revisit this ADR before writing the tool.

## Invariants

1. **A service secret must never reach an agent process.** `src/agent.rs:135`
   is the only PTY spawn site; the env it builds must be derived from the
   daemon's own environment, never from a resolved service env map. An agent has
   a shell, network access, and writes code on request. This boundary is not what
   makes that safe: a process under the same UID can read `/proc/<pid>/environ`
   of a running service regardless. What it removes is the silent path — an agent
   that never receives the value does not leak it by accident, by echoing its own
   environment, or by a dependency reading it during install. Deliberate
   exfiltration is out of this ADR's reach and belongs to agent sandboxing
   (a separate record, not yet written). This is a boundary in the spawn path, not a property of how
   the code happens to be wired today. Test it directly: spawn an agent with a
   service running and assert the secret is absent from its env.
2. **Every service log line passes redaction before it enters `logs`.** Redaction
   belongs inside `ManagedService::push_log` (`src/service/mod.rs:104`), not at any
   call site. An app that prints its own `DATABASE_URL` at startup would
   otherwise hand a password to whatever calls `read_service_logs` seconds
   later, and the caller is usually an agent. Match the literal value plus its
   base64 and percent-encoded forms, because a bearer token and a basic-auth
   header are the two most common ways a secret shows up in a log wearing a
   disguise. `PortForward` keeps a separate buffer (`src/portforward.rs:106`)
   served by `read_portforward_logs`, but no resolved secret reaches a
   port-forward process, so it is out of scope here; revisit if that changes.
3. **An unresolvable reference fails the service.** This is new behaviour, not
   an extension of the port rule: `interpolate_env` delegates to `regex_replace`
   (`src/ports/mod.rs:129`), which deliberately leaves an unresolvable
   placeholder literal and keeps scanning, and a test pins that
   (`src/ports/mod.rs:234`). Ports can survive it. A literal `ref+sops://...` in
   an `Authorization` header is either a dead service or a request sent to a
   third party with a placeholder string in it, so references need the opposite
   default.
4. **Plaintext never reaches disk, and that includes the private key.** Not a
   temp file, not a `.env` the daemon writes and deletes, not a cache, not a
   key file the daemon writes "just for this run". Decrypt into memory, put it
   in the child's env, drop it. The identity on disk is passphrase-encrypted and
   is decrypted once per session into memory, so the thing an agent or a
   `postinstall` script could read is never in the clear on the filesystem.

   "In memory" needs the OS layer to mean anything. Hold the identity and
   resolved values in `zeroize`-backed types, `mlock` the pages, set
   `madvise(MADV_DONTDUMP)` and `RLIMIT_CORE=0`, and prefer `memfd_secret` where
   the kernel has it. Two limits to keep in mind rather than trust away: `mlock`
   is page-granular, so unrelated secrets can share a page, and `MADV_DONTDUMP`
   is advisory. What actually stops a sibling process from reading the daemon's
   memory is Yama `ptrace_scope=1` (the Ubuntu default), which permits attaching
   only to descendants — and an agent is the daemon's child, not its ancestor.
   On macOS `task_for_pid` requires root.
5. **The escape hatch is tested, not documented.** If `sops exec-env` stops
   producing the same environment as warpforge, the lock-in has arrived and
   nobody will notice from the code.
6. **Removing a handle is forward-only, and the prod tier must rotate.** A
   removed recipient cannot decrypt anything committed afterwards, but keeps
   whatever their clone already holds: they still hold the key that wraps the
   data key in those older revisions, and no `sops rotate` reaches back into git
   history. For dev and staging that is accepted and needs no ceremony. For the
   prod tier the values must be rotated at the source, so removal from
   `secrets.prod.enc.yaml` is a two-step operation the UI requires rather than
   suggests: drop the recipient, then rotate every value in the file. That stays
   affordable only while the prod tier has one recipient. If it grows to a team,
   this invariant is the first thing that quietly stops happening. Word every
   removal confirmation as "no access to future changes", never as "access
   revoked".

   Rotation is load-bearing twice over. It is what makes forward-only revocation
   acceptable, and it is also the answer to ciphertext living in git history
   forever: a value that changes on a schedule has no long-term worth to whoever
   kept a copy. Both arguments rest on the same habit, so if rotation stops
   happening the design has two holes and neither is visible from the code.

7. **Document the limit, never a recipe, and never claim more than we do.** The
   readable-`/proc/<pid>/environ` behaviour is documented kernel behaviour in
   `proc_pid_environ(5)`, not a finding of ours; hiding it delays no attacker and
   misinforms the one person who needs it — the developer deciding whether a
   production credential belongs in this file. So the README states the scope
   plainly ("secrets arrive as environment variables; a process running as you
   can read another process's environment; this does not defend against code
   running as you") and carries no step-by-step exfiltration walkthrough,
   because that helps none of our users. The claim to avoid, in docs, changesets,
   and marketing alike: "an agent cannot read your secrets". What is true and
   defensible once the sandboxing record lands is narrower — a compromised agent cannot reach
   the secret store, and cannot send outward what it did reach.
