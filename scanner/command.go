package scanner

import "strings"

// credentialFlags lists CLI flags whose value must never reach reports.
var credentialFlags = map[string]struct{}{
	"-p":         {},
	"--password": {},
	"-H":         {},
	"--hashes":   {},
}

const maskedCredential = "***"

// MaskCredentials returns a copy of args where the values of credential flags
// are replaced with a placeholder. Both `--password value` and `--password=value`
// forms are handled. Other args are passed through unchanged.
func MaskCredentials(args []string) []string {
	out := make([]string, 0, len(args))
	maskNext := false
	for _, a := range args {
		if maskNext {
			out = append(out, maskedCredential)
			maskNext = false
			continue
		}

		if eq := strings.IndexByte(a, '='); eq > 0 {
			if _, ok := credentialFlags[a[:eq]]; ok {
				out = append(out, a[:eq]+"="+maskedCredential)
				continue
			}
		}

		if _, ok := credentialFlags[a]; ok {
			out = append(out, a)
			maskNext = true
			continue
		}

		out = append(out, a)
	}

	if maskNext {
		out = append(out, maskedCredential)
	}

	return out
}
