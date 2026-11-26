package scanner

import "strings"

// credentialFlags lists CLI flags whose value must never reach reports.
var credentialFlags = map[string]struct{}{
	"-p":         {},
	"--password": {},
	"-H":         {},
	"--hashes":   {},
	"--aes-key":  {},
}

const maskedCredential = "***"

// boolShortFlags are the short flags that take no value, so a bundle such as
// -kpSecret goes on to the next letter after them.
const boolShortFlags = "hk"

// maskShortBundle masks a credential in a bundle of short flags: -pSecret,
// -HHash or -kpSecret. masked is the argument to print; maskNext is set when
// the bundle ends with a credential flag whose value is the next argument.
func maskShortBundle(a string) (masked string, maskNext bool) {
	if len(a) < 2 || a[0] != '-' || a[1] == '-' {
		return a, false
	}
	for i := 1; i < len(a); i++ {
		switch c := a[i]; {
		case strings.IndexByte(boolShortFlags, c) >= 0:
			continue
		case c == 'p' || c == 'H':
			if i == len(a)-1 {
				return a, true
			}
			return a[:i+1] + maskedCredential, false
		default:
			// a flag with its value attached, such as -utester
			return a, false
		}
	}
	return a, false
}

// MaskCredentials returns a copy of args where the values of credential flags
// are replaced with a placeholder: `--password value`, `--password=value`,
// `-p value`, `-pvalue` and bundles such as `-kpvalue`. Other args are passed
// through unchanged.
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

		masked, next := maskShortBundle(a)
		out = append(out, masked)
		maskNext = next
	}

	if maskNext {
		out = append(out, maskedCredential)
	}

	return out
}
