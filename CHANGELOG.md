# Changelog

All notable changes to sharefinder are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Release notes on GitHub are taken
from the section of the released version.

## [Unreleased]

### Changed

- `--output-html NAME` replaces `--html`: the report is named like every
  other output and needs no `--output-json` or `--output-xml`. `--html` is
  removed. `sharefinder report` takes `--output-html` too.
- `--recurse` descends into directory symlinks and junctions again, so the
  domain folder in SYSVOL, a junction, is listed with its policies and
  scripts. `--disable-follow-links` skips them; `--follow-links` is removed.
  The JSONL scan record says whether links were followed (`follow_links`).
- `--depth` counts the levels listed, the share root being 1, and `0`, the
  default, lists every level: `--depth 5` meant 5 levels below the root, and
  5 was the default. A directory that lists exactly what a directory above
  it listed, which a link back up the tree does, is not listed again, so the
  walk ends without a depth limit; the scan warns when it cuts such a loop.
- The discovery sweep runs 64 probes at a time with a 2 s timeout
  (`--discovery-threads`, `--connect-timeout`), through `--proxy` too; it ran
  500 at a time with 1 s, and 50 with `--timeout` through `--proxy`.
  `--disable-discovery` replaces `--no-discovery`.
- `--max-auth-failures` is 0 by default: logons go to every target at once
  and a wrong password reaches all of them, which can lock the account out.
  `--max-auth-failures 1`, the default until now, sends logons one at a time
  until one succeeds and stops the scan at the first rejected logon.
- `hunt --resolver` says in its help what it does: the DNS server that
  resolves the computer names, the DC by default.

### Fixed

- The HTML report of 1.5.0 lost what earlier reports showed for each host:
  its details, its shares and the listing of each share, directory by
  directory. It is back, under "By host". A listing is drawn when it is
  opened (at once in a small scan) and shows at most 5,000 entries, so large
  scans stay fast; the Files table has every file. A listing says when it
  holds links and junctions that were not followed.
- `--resume` warned of a different command when the scan used
  `--output-relay-list`.
- `hunt --help` showed `--active-within=90d`, which reads as a default: there
  is none, and without `--active-within` every computer is scanned. The help
  now shows `--active-within=DURATION` and says so.

## [1.5.0] - 2026-11-26

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
- `sharefinder matrix`: a null session, a guest session and every given
  account are tested on each host in one pass, printed as one row per share
  (`DATA  null:R  guest:R  tester:RW`). Each account has its own lockout guard.
- `--aes-key` for Kerberos (SMB and LDAP), a password prompt when `-p` is not
  given, and the `SHAREFINDER_PASSWORD` environment variable. Without a
  password and without a terminal, sharefinder stops instead of trying an
  empty password (`-p ''` tests one on purpose).
- The negotiated SMB dialect is reported (host line, JSONL, XML, HTML), and
  `--output-relay-list` writes the hosts that do not require signing, taken
  from the negotiation, also when the logon is refused.
- `hunt` skips disabled computer accounts (`--include-disabled` keeps them),
  takes `--active-within 90d`, adds the servers DFS links point to within the
  hunted domains (others are named and skipped), shows the operating system
  recorded in AD, and `--ldap-only` lists the computers without scanning them.
- The HTML report shows the identity of each host and share row, which a
  matrix scan records per identity.
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
- The Kerberos LDAP bind uses the gokrb5 fork that go-smb uses, so
  jcmturner/gokrb5 and seven modules only it needed are no longer
  dependencies.

### Fixed

- A password or hash attached to its short flag (`-pSecret`, `-Hhash`) was
  written unmasked into the XML header (and the new JSONL scan record and HTML
  report).
- Control characters in share names, remarks and error texts from scanned
  servers could reach the terminal through warnings and errors; every message
  now shows them escaped.
- `--threads 0` hung; it is refused.
- Null and guest scans reported `signing:false` for every host; the signing
  requirement now comes from the negotiation, for every session type.
- `hunt --forest` read every domain from the Global Catalog, which holds
  neither the operating system nor, for other domains, the last logon time:
  their computers came without an OS and `--active-within` dropped them all.
  The search of the forest root also returned the computers of its child
  domains, which were then counted and scanned twice. Each domain is now asked
  on one of its own DCs; the Global Catalog is used, with a warning, only for a
  domain none of whose DCs answers, or with `-k`, whose tickets are for the
  user's own realm, and only that domain's own computers are taken from it.
- `hunt -k` was refused by Active Directory ("AcceptSecurityContext error,
  data 57"): the Kerberos request asked for mutual authentication without
  requiring it.
- `hunt -k --proxy` sent the Kerberos exchanges of the LDAP bind straight to
  the KDC instead of through the proxy; they now go through it, over TCP.
- A Kerberos reply from the LDAP server with a truncated encrypted part
  crashed `hunt -k`; it is refused.
- `--debug` reported "failed to disconnect tree" for every share that go-smb
  had already disconnected.
- `hunt -k` with an `ldap/` service ticket from impacket's getST failed the
  bind ("wrong Token ID. Expected 0504, was 6030"): such tickets carry an RC4
  session key, and the RC4 wrap tokens of the bind's last step (RFC 4757) are
  now supported.
- `KRB5CCNAME=FILE:/path` left the SMB logons without the tickets: go-smb
  reads the variable as a bare path. The prefix is removed at start.
- A ticket cache without a TGT and without a ticket for the DC's `ldap/`
  service gave "No usable TGT or ST found in CCache"; the error now names the
  tickets the cache holds: with service tickets only, `--dc-hostname` must be
  the host name in the `ldap/` ticket.

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
