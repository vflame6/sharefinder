package scanner

import (
	"fmt"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/vflame6/sharefinder/utils"
	"slices"
	"strings"
	"sync"
)

func authThread(s <-chan bool, options *Options, wg *sync.WaitGroup) {
	for {
		select {
		case <-s:
			wg.Done()
			return
		default:
			host, ok := <-options.Target
			if !ok {
				wg.Done()
				return
			}
			smbOptions := GetNTLMOptions(host, options.Username, options.Password, options.Domain)
			session, err := GetSession(smbOptions)
			if err != nil {
				fmt.Printf("Error getting session: %v\n", err)
				continue
			}
			defer session.Close()

			isSigningRequired := session.IsSigningRequired()

			if !session.IsAuthenticated() {
				fmt.Printf("[-] Login failed on %s\n", host)
			}

			share := "IPC$"
			err = session.TreeConnect(share)
			if err != nil {
				fmt.Println(err)
				continue
			}
			defer session.TreeDisconnect(share)
			f, err := session.OpenFile(share, "srvsvc")
			if err != nil {
				fmt.Println(err)
				continue
			}
			defer f.CloseFile()

			bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
			if err != nil {
				fmt.Println(err)
				continue
			}

			shares, err := bind.NetShareEnumAll(host)
			if err != nil {
				fmt.Println(err)
				continue
			}

			targetInfo := session.GetTargetInfo()

			fmt.Println(utils.SPrintHostInfo(host, targetInfo.GuessedOSVersion, targetInfo.DnsComputerName, targetInfo.DnsDomainName, isSigningRequired, false))
			fmt.Printf("%-16s %-16s %-16s\n", "Share", "Permissions", "Decription")
			fmt.Printf("%-16s %-16s %-16s\n", strings.Repeat("-", 5), strings.Repeat("-", 11), strings.Repeat("-", 10))

			for _, share := range shares {
				var permissions []string

				if slices.Contains(options.Exclude, share.Name) {
					continue
				}

				session.TreeConnect(share.Name)
				_, err := session.ListShare(share.Name, "", false)
				if err == nil {
					permissions = append(permissions, "READ")
				} else {
					continue
				}

				fmt.Printf("%-16s %-16s %-16s\n", share.Name, strings.Join(permissions, ","), share.Comment)

				// TODO: implement a check for write permission
				//if share.Writable {
				//	permissions = append(permissions, "WRITE")
				//}

				// list directories recursively if enabled
				if options.List {
					fmt.Println("List share")
					listShare(session, share.Name, false)

					fmt.Println("List share recursively")
					listShare(session, share.Name, true)
				}

				session.TreeDisconnect(share.Name)
			}
		}
	}
}
