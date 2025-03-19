# sharefinder

**Active network shares enumeration tool.**

---

`sharefinder` is a network share discovery tool that enumerates shares, permissions, files and vulnerabilities in networks and domains.

## Features

Main commands:

- `hunt`: hunt network shares inside Active Directory domain
- `auth`: scan network for shares with specified credentials
- `anon`: search for shares accessible by anonymous/guest account

## Usage

```shell
sharefinder -h
```

Here is the help menu for the tool.

```yaml
usage: sharefinder [<flags>] <command> [<args> ...]

  Sharefinder is a network share discovery tool that enumerates shares, permissions, files and vulnerabilities in networks and domains.

Flags:
  -h, --[no-]help              Show context-sensitive help (also try --help-long and --help-man).
  -o, --output=""              file to write output to
  --threads=1              number of threads (default 10)
  --timeout=5s             seconds to wait for connection (default 5)
  -e, --exclude="ADMIN$,IPC$"  share names to exclude (default ADMIN$,IPC$
  --[no-]list              attempt to list shares (default false)
  -s, --search=SEARCH          pattern to search through files
  --[no-]version           Show application version.

Commands:
  help [<command>...]
  auth --username=USERNAME --password=PASSWORD [<flags>] <target>
```

## Installation

`sharefinder` requires **go1.24** to install successfully.

```shell
go install -v github.com/vflame6/sharefinder@latest
```
