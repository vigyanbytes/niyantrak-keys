# niyantrak-keys

[![CI](https://github.com/vigyanbytes/niyantrak-keys/actions/workflows/ci.yml/badge.svg)](https://github.com/vigyanbytes/niyantrak-keys/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`niyantrak-keys` rotates SSH keys **one connection at a time**, without locking you out. It plans first, it runs
dry by default, and it writes every step to an audit log that holds fingerprints, never key material.

It is the open-source command-line core of [Niyantrak](https://github.com/vigyanbytes/niyantrak), the governance
control plane from VigyanBytes. You can use it on its own with a local `connections.json`, or enrol the device
with a Niyantrak control plane.

Private keys never leave the device that owns them. The tool only moves public key lines.

## The rule

**One key per connection.** A connection is *source device + source user → target device + target user*.

| What | Form | Example |
|---|---|---|
| Key file | `~/.ssh/<source>-<target>-<user>` (no date) | `~/.ssh/ws-01-gpu-01-alice` |
| Key comment | `<source>-<target>-<user>-<YYYYMMDD>` (the date lives in the comment) | `ws-01-gpu-01-alice-20261025` |
| `~/.ssh/config` | `Host <target>` → `IdentityFile` + `IdentitiesOnly yes`, written as a marked block | |

`IdentitiesOnly yes` makes sure ssh offers only that connection's key, so one leaked or stale key never opens a
second door. Two connections that would share a key file are refused.

## The 7-step safety contract

Dry run is the default. Nothing changes until you pass `--apply`. Per connection, one target, never partial:

| # | Step | On failure |
|---|---|---|
| 1 | **due**: age from `<key>.rotated-at` (else the `.pub` date) ≥ `max_age_days`, or still on the legacy key | not due → skip quietly |
| 2 | **preflight**: log in to the target with the CURRENT key | skip today, retry next run; alert only when overdue by `overdue_alert_days` |
| 3 | **stage**: new key at `<key>.new`; the current key is untouched | delete the partial key, nothing else changed |
| 4 | **install**: append the new public key to the target's authorized keys | remove it again, old key unchanged |
| 5 | **verify**: log in with ONLY the new key (`ssh -F /dev/null -i <key>.new -o IdentitiesOnly=yes ...`) | remove the new key from the target, delete it here, old key unchanged, alert |
| 6 | **switch**: old → `<key>.retired-<ts>` (kept `retired_keep_days`), new → `<key>`, write `.rotated-at`, update `~/.ssh/config` | roll back the renames, remove the new key from the target |
| 7 | **retire**: remove the old public key from the target, re-verify with the current key | re-verify failure → **critical** alert with the exact recovery command |

Every ssh call is strict (`-F /dev/null -i <key> -o IdentitiesOnly=yes -o BatchMode=yes
-o StrictHostKeyChecking=yes`), so your ssh config, the agent or another key can never make a check pass. Key
lines travel to the target on stdin, never on a command line. A leftover `<key>.new` from a crashed run is
removed from the target before a new key is staged. The first rotation of a connection still on a shared legacy
key (for example `~/.ssh/id_ed25519`) is the migration: the legacy file stays where it is, and its public key is
removed only from targets that no other connection still reaches with it.

## Install

### Release binaries

Download the binary for your platform from
[Releases](https://github.com/vigyanbytes/niyantrak-keys/releases), check it against `SHA256SUMS`, and put it on
your `PATH`:

```bash
sha256sum -c SHA256SUMS --ignore-missing
install -m 0755 niyantrak-keys-v0.1.0-linux-x86_64 ~/.local/bin/niyantrak-keys
niyantrak-keys version
```

### From source

Needs Rust (stable) and, at run time, the OpenSSH client (`ssh`, `ssh-keygen`).

```bash
git clone https://github.com/vigyanbytes/niyantrak-keys
cd niyantrak-keys
cargo build --release -p keys-cli        # target/release/niyantrak-keys
# or
cargo install --git https://github.com/vigyanbytes/niyantrak-keys --tag v0.1.0 keys-cli
```

## Quick start

1. Write the connection list to `~/.config/niyantrak/connections.json` (Windows:
   `%USERPROFILE%\.niyantrak\connections.json`), or pass `--config FILE`. See
   [`examples/connections.json`](examples/connections.json).

   ```json
   {"ssh_rotation": {"max_age_days": 90, "overdue_alert_days": 14, "retired_keep_days": 30,
     "connections": [{"source": "ws-01", "user": "alice", "target": "gpu-01", "target_user": "alice"}]}}
   ```

2. See what would happen. `plan` is read-only:

   ```bash
   niyantrak-keys plan              # age, due date, reachability, drift on targets
   niyantrak-keys rotate            # dry run: prints the steps it would take
   ```

3. Rotate for real, one connection first:

   ```bash
   niyantrak-keys rotate --apply --connection ws-01-gpu-01-alice
   ```

4. Once you trust it, run `niyantrak-keys rotate --apply` from a daily timer (systemd timer, cron, Task
   Scheduler). Only due connections are touched.

Optional per connection: `hostname`/`port` (else `ssh -G <target>`), `target_os` (`linux` | `windows`),
`authorized_keys` (Linux default `~/.ssh/authorized_keys`; Windows default `administrators` =
`C:\ProgramData\ssh\administrators_authorized_keys`, or `user`), `legacy_key`, and `ssh_options` (only
`ProxyJump`, `HostKeyAlias`, `ConnectTimeout`, `ServerAliveInterval`, `ServerAliveCountMax`, `AddressFamily`;
anything that can run a command is refused, because the list may come from a control plane).

A device rotates only the connections whose `source` is this device and whose `user` is the account running the
tool. Others are listed as "rotated on other devices".

## Commands

```
niyantrak-keys plan   [--no-probe] [--json]                     # read-only: age, due, reachability, drift
niyantrak-keys rotate [--apply] [--connection ID] [--force] [--json] [--alert-cmd PROG]
niyantrak-keys card   [--role R]                                # this device's node card and its sha256
niyantrak-keys enrol  [--host-key PATH] [--role R] <invite>     # root / Administrator
niyantrak-keys status                                           # enrolment state
niyantrak-keys identity                                         # who is acting, derived from the OS
niyantrak-keys version
common: --config FILE  --home DIR  --node NAME  --known-hosts FILE
```

Exit codes: `0` ok, `1` error, `2` a rotation raised an alert. `--alert-cmd` receives each alert (and each
successful rotation) as JSON on stdin; that is where a notifier (email, chat) plugs in.

## Audit and identity

- `~/.local/state/niyantrak/ssh-rotation.jsonl` (Windows `%USERPROFILE%\.niyantrak\state\`): one line per step
  with old and new **fingerprints** and the person who ran it. Never key material.
- `ssh-rotation.5w.jsonl`: the same steps as Niyantrak `niyantrak.6w/1` events (who, whom, what, where, why,
  which, plus when) that `niyantrak telemetry ingest` accepts.
- The person is derived from the OS login (NSS on Unix, so local, SSSD, authd, Kanidm and LDAP accounts resolve
  the same way; the account SID on Windows) plus a stable directory id. Nothing is typed in and no names are
  hard-coded.

## Joining a control plane and rotation in the alpha

In the 0.1 alpha, both joining and rotation are deliberately manual:

- **Joining.** The operator issues a single-use join token in the Niyantrak panel. On the device, run
  `sudo niyantrak-keys enrol` (Administrator on Windows) and paste the invite. The device signs its node card with
  its SSH host key and posts it over TLS **pinned to the fingerprint in the invite**; a wrong pin is refused
  before the token is sent. The node stays `pending` until the operator approves it under Fleet.
- **Connection list.** The control-plane endpoint that will deliver `connections.json` to enrolled devices is not
  served yet (the tool treats a 404 as "not offered"). Place `connections.json` on each device yourself.
- **Rotation.** Run `plan`, then `rotate`, then `rotate --apply`. Schedule `rotate --apply` yourself when you are
  ready. Windows targets are supported but have had less real-world use: run the first rotation of a Windows
  target as a dry run, then once with someone watching.

## Tests

```bash
cargo test --workspace                                   # every step and failure branch on an in-memory transport
cargo test -p keys-engine --features real-sshd           # + real rotations against a throwaway local sshd
NIYANTRAK_SRC=/path/to/niyantrak cargo test -p keys-engine --test niyantrak_compat
```

The `real-sshd` tests start `sshd` as the current user on `127.0.0.1` from a temp dir, with its own host key and
authorized_keys, and kill it afterwards. Nothing touches your real `~/.ssh`: every test uses a temp home. Without
the feature they are reported as ignored. The compatibility tests run against a checkout of the
[Niyantrak core](https://github.com/vigyanbytes/niyantrak) and skip when `NIYANTRAK_SRC` is not set.

## Layout

```
crates/keys-engine   library: model, plan, rotate (7 steps), transport (system ssh / in-memory), audit + 6W,
                     identity (from the OS), enrol (node card, pinned-TLS join), features, client facade
crates/keys-cli      the niyantrak-keys binary
examples/            connections.json
```

## The Niyantrak app

The **Niyantrak desktop app** (Windows and Linux) is built on this engine and adds connection cards with key-age
rings, guided rotation with live progress of the 7 steps, desktop notifications when keys are due, and a guided
join. It is a commercial product from [VigyanBytes](https://vigyanbytes.com); write to info@vigyanbytes.com.
Everything the app does to keys goes through the code in this repository.

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md): Developer Certificate of Origin sign-off, no CLA.
- [SECURITY.md](SECURITY.md): report vulnerabilities privately, never in a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
