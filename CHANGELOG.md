# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-25

First public release (alpha).

### Added

- `keys-engine` library: per-connection key model (`<source>-<target>-<user>` file, dated comment,
  `IdentitiesOnly`), read-only plan (age, due, reachability, drift on targets), the 7-step rotation contract with
  an injectable transport (system OpenSSH or in-memory), JSONL audit with fingerprints only, Niyantrak
  `niyantrak.6w/1` events, identity derived from the OS (NSS on Unix, account SID on Windows), node card and
  enrolment over TLS pinned by fingerprint.
- `niyantrak-keys` CLI: `plan`, `rotate [--apply]`, `card`, `enrol`, `status`, `identity`, `version`. Dry run by
  default.
- Linux and Windows targets (`authorized_keys` and `administrators_authorized_keys`).
- Tests for every rotation step and failure branch, plus optional real rotations against a throwaway local sshd
  (`--features real-sshd`).

[Unreleased]: https://github.com/vigyanbytes/niyantrak-keys/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vigyanbytes/niyantrak-keys/releases/tag/v0.1.0
