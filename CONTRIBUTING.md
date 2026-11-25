# Contributing to sharefinder

Thanks for helping. Bug reports, ideas and pull requests are all welcome.

## Development

sharefinder needs the Go version in `go.mod` or newer.

```shell
go build -o sharefinder .
```

Before you open a pull request, run what CI runs:

```shell
test -z "$(gofmt -l .)"
go vet ./...
go test -race -cover ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Keep changes focused, add a test for every bug you fix and every feature you
add, and add a line to the `[Unreleased]` section of `CHANGELOG.md`.

### Testing against a server

Unit tests do not need a network. For manual checks a Samba container is the
quickest target, for example with `map to guest = bad user`, a writable share,
a read-only guest share and a share containing a symlink loop. Windows behaves
differently in several places (ACLs, guest mapping, Kerberos), so changes in
those areas also need a check against a Windows domain.

## Release checklist

1. CI is green on `main`.
2. Run the Windows lab checks against a test domain (for example GOAD):
   - `hunt` with a password, with `--hashes` and with `-k`, also `--forest`.
   - LDAP: LDAPS, StartTLS, and plain LDAP refused without
     `--allow-plaintext-ldap`.
   - Kerberos `auth -k` against a host name, and a wrong password stops after
     one failed pre-authentication.
   - `guest` and `null` against hosts with Guest enabled and disabled.
   - `--write-check mask` and `--write-check file` report the same shares on
     shares with Windows ACLs.
3. Move the `[Unreleased]` entries of `CHANGELOG.md` to a new version section
   with the release date.
4. Tag the release (`git tag vX.Y.Z && git push origin vX.Y.Z`). The release
   workflow builds the binaries and the container image and takes the release
   notes from `CHANGELOG.md`.
