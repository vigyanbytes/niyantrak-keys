# Security policy

`niyantrak-keys` changes who can log in to your machines, so we treat security reports as the highest priority.

## Reporting a vulnerability

Please report privately, never in a public issue, pull request or discussion. Either:

- use GitHub's **private vulnerability reporting**: the "Report a vulnerability" button under this repository's
  **Security** tab, or
- e-mail **info@vigyanbytes.com** with "SECURITY niyantrak-keys" in the subject.

Please include the version (`niyantrak-keys version`), the platform, the steps to reproduce and the impact you
expect. Do not include real private keys or credentials; a fingerprint or a throwaway key is enough.

## What to expect

- We acknowledge your report within 3 working days.
- We confirm or rule out the issue and share a plan within 10 working days.
- We fix it, publish an advisory and credit you (unless you prefer otherwise). Please give us up to 90 days before
  public disclosure; we will tell you if we need less or more.

## In scope

Anything that could lock a user out, leave a key usable after it should have been retired, expose key material
(on disk, in logs, on a command line, over the network), bypass the TLS pin during enrolment, let a connection list
run a command through ssh options, or misattribute the person in the audit log.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
