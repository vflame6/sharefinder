# Changelog

All notable changes to sharefinder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Release notes on GitHub are taken
from the section of the released version.

## [Unreleased]

## [1.4.1] - 2026-11-26

Safety and correctness release: every fix below could hurt a client network or
produce a wrong finding.

### Fixed

- A host that accepted TCP but never answered hung its worker forever. Every SMB
  and LDAP read and write is now bounded by `--io-timeout` (default `30s`), also
  through `--proxy`.
- Ctrl+C now stops the scan at once: open connections are closed, partial
  results are written, the XML file is terminated and the exit code is 130. A
  second Ctrl+C exits immediately.
- A wrong password no longer reaches every target. Credentials go to one target
  until a logon succeeds, and the scan stops after `--max-auth-failures`
  rejected logons (default `1`; `0` disables the guard). Logon failure, locked
  out, disabled, expired and must-change statuses, and the matching Kerberos
  errors, count as rejections. Once a logon has succeeded, a host outside the
  account's domain (or any host with `--local-auth`) that refuses the
  credentials is reported for that host only. Null and guest scans are not
  limited.
- Servers that map failed logons to Guest no longer produce results under the
  wrong identity. The session type (`user`, `guest`, `null`) is shown on the
  host line and in XML and HTML; in `auth` and `hunt` a guest-mapped logon
  counts as rejected credentials.
- The write check can now leave no trace: `--write-check mask` opens the share
  root with write access masks and creates nothing, reporting `WRITE`,
  `WRITE (SUBDIR)` and `WRITE (ACL)`; `--write-check off` skips it. Print
  queues, devices and IPC shares are never write-checked. The file probe now
  removes its file when the write fails and reports the full path of any file
  that may remain.
- `--recurse` is bounded: `--depth` (default `5` levels below the share root),
  directory symlinks and junctions are skipped unless `--follow-links`, and
  `--max-files` stops a share after that many entries. A symlink loop used to
  recurse until the server gave up.
- Targets: hostnames and FQDNs are accepted (and kept for the Kerberos SPN),
  `/31` and `/32` yield their hosts, full ranges such as
  `10.0.0.1-10.0.0.9` work, long comma-separated lists work, duplicate and
  overlapping entries are scanned once, target files accept `#` comments, and
  a target or exclusion file that does not exist is an error.
- `--exclude-hosts` keeps addresses, blocks and hostnames out of scope:
  excluded hostnames also exclude their IP addresses, a short name also
  excludes its FQDNs, and a target name that resolves into an excluded block is
  skipped.
- `hunt` no longer falls back from a failed Kerberos bind to a simple bind.
  When LDAPS and StartTLS both fail, a password is used in an NTLM bind instead
  of a simple bind, so it is never sent in clear text; `--allow-plaintext-ldap`
  permits a simple bind there.
- Connections that failed during negotiation or logon are closed instead of
  leaking, and a connection that waited for the first logon is negotiated again
  instead of failing.
- After Ctrl+C, shares whose checks were cut short are left out of the results
  instead of being reported as not readable and not writable.
- `--timeout` must be greater than 0.
- The guest module ends with "Finished executing guest module" (was "anon"),
  and file listings head the name column `Name` (was `ShareName`).

### Added

- CI on every push and pull request: gofmt, go vet, tests with the race
  detector, govulncheck, builds on Linux, Windows and macOS, and the Docker
  image.
- Container image on GitHub Container Registry, published with each release:
  `ghcr.io/vflame6/sharefinder`.
- `SECURITY.md`, `CONTRIBUTING.md` and issue templates.

### Changed

- `--write-check` defaults to `file`, the previous behaviour, until `mask` has
  been compared with `file` against Windows ACLs.
- `--recurse` now stops at depth 5 by default; use `--depth` to go deeper.
- Release binaries are built with the current stable Go toolchain; the Docker
  build uses Go 1.27.
- go-pkcs12 updated to v0.7.2 (GO-2026-5052).
