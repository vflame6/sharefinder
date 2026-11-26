package scanner

import (
	"path"
	"strings"
)

// File tags flag names worth a content scanner's look. They are derived from
// the name alone; sharefinder never reads file contents.
const (
	TagConfig   = "config"
	TagScript   = "script"
	TagSecret   = "secret"
	TagDatabase = "database"
	TagBackup   = "backup"
)

// secretNames are files that commonly hold credentials or keys.
var secretNames = map[string]bool{
	"unattend.xml": true, "autounattend.xml": true, "sysprep.inf": true, "sysprep.xml": true,
	"groups.xml": true, "services.xml": true, "scheduledtasks.xml": true, "datasources.xml": true, "drives.xml": true, "printers.xml": true,
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	".git-credentials": true, ".netrc": true, ".pgpass": true, "credentials.xml": true, "ntds.dit": true,
	"sam": true, "system": true, "security": true,
}

// extensionTags maps lower-case extensions to their tag.
var extensionTags = map[string]string{
	".config": TagConfig, ".conf": TagConfig, ".cfg": TagConfig, ".ini": TagConfig, ".yaml": TagConfig, ".yml": TagConfig,
	".properties": TagConfig, ".env": TagConfig, ".toml": TagConfig,
	".ps1": TagScript, ".psm1": TagScript, ".bat": TagScript, ".cmd": TagScript, ".vbs": TagScript, ".sh": TagScript, ".py": TagScript,
	".kdbx": TagSecret, ".kdb": TagSecret, ".pfx": TagSecret, ".p12": TagSecret, ".pem": TagSecret, ".key": TagSecret,
	".ppk": TagSecret, ".ovpn": TagSecret, ".rdg": TagSecret, ".keytab": TagSecret,
	".mdf": TagDatabase, ".ldf": TagDatabase, ".sqlite": TagDatabase, ".db": TagDatabase, ".sdf": TagDatabase,
	".accdb": TagDatabase, ".mdb": TagDatabase,
	".bak": TagBackup, ".vhd": TagBackup, ".vhdx": TagBackup, ".vmdk": TagBackup, ".wim": TagBackup, ".tib": TagBackup,
}

// FileTags returns the tags for a file name, or nil.
func FileTags(name string) []string {
	lower := strings.ToLower(name)
	if secretNames[lower] {
		return []string{TagSecret}
	}
	if tag, ok := extensionTags[path.Ext(lower)]; ok {
		return []string{tag}
	}
	return nil
}
