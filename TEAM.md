# Team setup, step by step

This page is for the whole team, not just the person who set the repo up.
Follow the steps in order. Each section says who runs it.

Two words you need:

- **Access list** — `.yett/secrets-access.yaml`, a committed file mapping a
  person to their public key. It contains no secrets.
- **Sync** — `yett access sync` rewraps the encrypted files so the people in the
  access list can read them. Only someone who can already read the files can
  run it, because it has to decrypt them first.

You do not need `sops` installed for any of this.

---

## 1. Repo admin, once: create the project

```sh
cd your-repo
yett init --tiers dev --handle your-github-handle
```

It asks for a passphrase twice, creates `.yett/`, `.sops.yaml`, and
`.env.refs`, and registers your public key. The passphrase protects the private
key in `~/.config/yett/dev.key.age`. It is never committed, and nothing can
answer the prompt for you.

Add the first secret:

```sh
printf 'postgres://localhost:5432' | yett set dev db/url
```

Create `.env.refs` if it is empty, so the app knows which variable comes from
where:

```
DATABASE_URL=ref+sops://.yett/secrets.dev.enc.yaml#/db/url
LOG_LEVEL=debug
```

Commit everything and push:

```sh
git add .env.refs .sops.yaml .yett/
git commit -m "add yett secrets for dev"
git push
```

Do not commit the key in `~/.config/yett/`. There is nothing to add; it lives
outside the repository.

---

## 2. Each developer, once per machine: register a key

Clone the repo, then run this from the repo root, with your own GitHub handle:

```sh
yett keygen --register your-github-handle --tier dev
```

It asks for a passphrase twice (choose one and keep it), writes
`~/.config/yett/dev.key.age`, adds your public key to
`.yett/secrets-access.yaml`, and refreshes `.sops.yaml`.

Commit your change and push it, or open a pull request:

```sh
git switch -c add-your-github-handle-key
git add .yett/secrets-access.yaml .sops.yaml
git commit -m "register your-github-handle age key"
git push -u origin HEAD
```

At this point you **cannot read existing secrets yet**. That is one more step,
and someone else runs it.

---

## 3. Repo admin: let the new key read existing files

After the registration is merged (or pushed), the admin pulls it:

```sh
git pull
yett access sync
```

`sync` asks for the admin passphrase, rewraps every encrypted file for the new
access list, and updates `.sops.yaml`. Commit and push:

```sh
git add .sops.yaml .yett/
git commit -m "sync recipients"
git push
```

Without this step the new developer sees a decryption error: the files are
still encrypted to the old key set.

---

## 4. The new developer: pull and read

```sh
git pull
yett get dev/db/url
```

It asks for the passphrase chosen in step 2, then prints the value.

Run the app the same way:

```sh
yett run -- npm run dev
```

---

## Day to day

Change a value:

```sh
printf 'new-value' | yett set dev db/url
git add .yett/secrets.dev.enc.yaml
git commit -m "rotate db url"
git push
```

`yett set` on a new key creates the entry; on an existing one it replaces it.
Never edit `.sops.yaml` by hand.

Edit a whole document:

```sh
yett edit dev
```

It opens `$EDITOR` on a RAM-backed copy and re-encrypts on save. Nothing
plaintext is written to disk. On Linux this needs `/dev/shm`; on macOS it
creates and ejects a small RAM disk.

Read one value in a script:

```sh
yett get dev/db/url
```

Check that everything is consistent before merging, exactly as CI does:

```sh
yett check
```

It exits 4 when the access list, `.sops.yaml`, and the encrypted files
disagree.

---

## Removing someone

Dev and staging:

```sh
yett access remove their-handle
yett access sync
git add .sops.yaml .yett/
git commit -m "remove their-handle"
git push
```

They lose access to everything committed after this. They keep whatever their
clone already has, because no rotation reaches back into git history.

Prod is different: removing a person there means every value in the prod file
must be rotated at its source first. Run `yett access remove their-handle`
without `--force-prod`: the command prints that duty and refuses, and you only
re-run it with `--force-prod` after the values are rotated.

---

## CI

CI needs its own key, and it does not have a terminal. Export a plaintext
identity into the CI secret store and point `--identity` at it:

```sh
yett check --identity "$CI_IDENTITY"
```

A plaintext identity is accepted only through `--identity` or
`YETT_IDENTITY`. The default path always expects a passphrase-encrypted key.

---

## When something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `passphrase ... decryption failed` | Wrong passphrase for this key | Re-run, check the passphrase; if it is lost, generate a new key in step 2 and ask an admin to sync |
| `decryption failed ... not a recipient` | Your key is in the list but the file has not been rewrapped | An admin runs `yett access sync` and pushes; then `git pull` |
| `no value at /db/url` | The pointer names a key that does not exist | Check the path in `.env.refs`; `yett get` uses the same pointers |
| `the access list and .sops.yaml disagree` (exit 4) | Someone edited `.sops.yaml` or the list by hand | An admin runs `yett access sync` and commits |
| `ref+sops://...` printed as the value | The variable was not resolved | Make sure the command runs through `yett run`, not directly |

---

## What is committed, and what is not

| Path | Committed | Contains |
| --- | --- | --- |
| `.env.refs` | yes | references and non-secret values |
| `.yett/secrets-access.yaml` | yes | handles and public keys |
| `.yett/secrets.<tier>.enc.yaml` | yes | encrypted values, cleartext keys |
| `.sops.yaml` | yes | generated recipient rules |
| `~/.config/yett/<tier>.key.age` | no | your passphrase-encrypted private key |
