package utils

import "fmt"

// func SPrintPermissionsTable() {
//
// }
func SPrintHostInfo(host, version, hostname, domain string, signing, smbv1 bool) string {
	return fmt.Sprintf("[+] %s %s (name:%s) (domain:%s) (signing:%v) (SMBv1:%v)", host, version, hostname, domain, signing, smbv1)
}
