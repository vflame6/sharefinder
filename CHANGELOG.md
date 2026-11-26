# Changelog

All notable changes to sharefinder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Release notes on GitHub are taken
from the section of the released version.

## [Unreleased]

### Added

- `--output-json` writes JSONL: one `scan`, `host`, `share`, `file` or `end`
  record per line, flushed as results arrive, so a killed scan keeps what it
  found. Every record carries the scan id, the identity and a `//host/share`
  UNC path, and file records carry tags (`config`, `script`, `secret`,
  `database`, `backup`).
- `--output-csv` writes one row per share for client deliverables; cells a
  spreadsheet would run as a formula are prefixed with `'`.
- `--output-unc` writes `//host/share` for each readable disk share, for
  content scanners. `--output-all` now also writes JSONL, CSV and the UNC list.
- `sharefinder report scan.jsonl` writes the HTML report of a JSONL scan, also
  of one that was cut short. The report keeps the scan as JSON and renders it
  with DataTables, so a million-file listing opens in a few seconds; every
  name is shown as text.
- `sharefinder diff old.jsonl new.jsonl` lists new shares, removed shares and
  permission changes.
- A progress line on stderr when it is a terminal: elapsed time, targets done
  and total, reachable hosts, shares and files.
- A closing summary: `Summary: 254 targets, 12 reachable, 10 authenticated,
  2 failed`.
- `--force` to overwrite existing output files.
- A discovery sweep: a TCP probe of the SMB port, 500 at a time with a 1 s
  timeout, so only hosts that answer wait for an SMB worker. 40 silent targets
  at `--timeout 2s` took 8 s and now take 1 s. `--discovery-threads`,
  `--connect-timeout` and `--no-discovery` control it; through `--proxy` it
  runs 50 at a time with the `--timeout`.
- `--max-conns-per-host` (default 2) lists the shares of one host over several
  connections, within `--threads`.
- `--resume scan.jsonl` continues an interrupted `--output-json` scan: finished
  hosts are not contacted again and finished shares are neither checked nor
  listed again.
- Homebrew: the repository is its own tap
  (`brew tap vflame6/sharefinder https://github.com/vflame6/sharefinder`); each
  release commits the updated cask to `Casks/`.
- Debian packaging in `debian/`, with the Go modules vendored into the orig
  tarball and a manual page generated from the help.

### Changed

- Results go to stdout; the banner, warnings, errors, progress and summary go
  to stderr.
- Failures are labelled by stage: connection, authentication or enumeration.
  Unreachable hosts are shown only with `--debug`.
- Results are streamed to the outputs as they are found instead of being held
  in memory until a host is done; memory stays flat on huge listings.
- `--html` renders from JSONL and no longer needs `--output-xml`; the report is
  named after `--output-json` or `--output-xml`. HTML is no longer rendered
  from XML.
- `-o plain.txt` writes `plain.txt` (not `plain.txt.txt`), and existing output
  files are not overwritten without `--force`.
- UNC paths name a host by the name it was scanned by, else by its IP address,
  never by the DNS name the server reports for itself.
- Host and share names, remarks and file names with control characters are
  escaped in the console output.
- `hunt` resolves computer names 32 at a time and scans each host as soon as
  its name resolves; computers without a DNS record are counted in a warning.
- Hosts whose SMB port answers but that do not negotiate SMB2 (SMB1-only
  devices, other services) are reported and counted as reachable and failed.
- go-smb v0.12.0; Go 1.26 is required to build. Dependabot opens one grouped
  pull request a week.

### Fixed

- A password or hash attached to its short flag (`-pSecret`, `-Hhash`) was
  written unmasked into the XML header (and the new JSONL scan record and HTML
  report).
- Control characters in share names, remarks and error texts from scanned
  servers could reach the terminal through warnings and errors; every message
  now shows them escaped.
- `--threads 0` hung; it is refused.

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
