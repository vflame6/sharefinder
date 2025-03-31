<h1 align="center">
  sharefinder
</h1>

<h4 align="center">Active network shares enumeration tool.</h4>

<p align="center">
<a href="https://goreportcard.com/report/github.com/vflame6/sharefinder" target="_blank"><img src="https://goreportcard.com/badge/github.com/vflame6/sharefinder"></a>
<a href="https://github.com/vflame6/sharefinder/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/vflame6/sharefinder/releases"><img src="https://img.shields.io/github/release/vflame6/sharefinder"></a>
</p>

---

`sharefinder` is a network share discovery tool that enumerates shares, permissions and files in networks and domains.

# Features

![sharefinder](static/sharefinder_demo.jpg)

Main commands:

- `hunt`: hunt network shares inside Active Directory domain
- `auth`: scan network for shares with specified credentials
- `anon`: search for shares accessible by anonymous/guest account

# Usage

```shell
sharefinder -h
```

Here is the help menu for the tool.

```yaml
usage: sharefinder [<flags>] <command> [<args> ...]

  sharefinder is a network share discovery tool that enumerates shares, permissions and files in networks and domains.

Flags:
  -h, --[no-]help              Show context-sensitive help (also try --help-long and --help-man).
  -o, --output=""              file to write output to (raw and xml)
  --[no-]html              output HTML (default false)
  --threads=1              number of threads (default 1)
  --timeout=5s             seconds to wait for connection (default 5s)
  -e, --exclude="IPC$,ADMIN$"  share names to exclude (default IPC$,ADMIN$)
  --[no-]list              list readable shares (default false)
  --[no-]recurse           list readable shares recursively (default false)
  --smb-port=445           target port of SMB service (default 445)
  --[no-]version           Show application version.

Commands:
  help [<command>...]
  anon <target>
  auth --username=USERNAME --password=PASSWORD [<flags>] <target>
  hunt --username=USERNAME --password=PASSWORD <dc>
```

# Installation

`sharefinder` requires **go1.24** to install successfully.

```shell
go install -v github.com/vflame6/sharefinder@latest
```
