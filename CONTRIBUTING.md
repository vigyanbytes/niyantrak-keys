# Contributing to niyantrak-keys

Thank you for helping. Bug reports, fixes, tests and documentation are all welcome.

## Ground rules

- **Safety first.** The 7-step rotation contract in the README is the product. A change that could leave a
  target without a working key, or that weakens a failure branch, will not be merged. New behaviour comes with a
  test for its failure branch, not only the happy path.
- **Dry run stays the default.** Nothing may change a key or a target without `--apply`.
- **No key material in logs, errors or test output.** Fingerprints only.
- **Fictional fixtures only.** Use `ws-01`, `gpu-01`, `edge-01`, `laptop-01`, users `alice`/`bob`, documentation
  addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.com`. Never real hostnames,
  addresses, user names or keys.

## Developer Certificate of Origin (DCO)

We do not use a Contributor License Agreement. Instead, every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/), which certifies that you wrote the
change or otherwise have the right to submit it under the Apache License 2.0:

```bash
git commit -s -m "rotate: explain why preflight was skipped"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. Pull requests with unsigned commits cannot be
merged; `git rebase --signoff main` adds the line to every commit of your pull request.

## Before you open a pull request

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p keys-engine --features real-sshd     # if you have an OpenSSH server installed (Linux/macOS)
```

CI runs the build and tests on Linux, Windows and macOS, clippy, and `cargo deny` (licences and advisories).

## Reporting security issues

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, as stated in
section 5 of the licence.
