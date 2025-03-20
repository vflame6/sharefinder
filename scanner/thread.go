package scanner

import (
	"fmt"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/utils"
	"log"
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
			var hostResult string
			var readableShares []string

			conn, err := NewNTLMConnection(host, options.Username, options.Password, options.Domain, options.Timeout)
			if err != nil {
				log.Println(err)
				continue
			}
			defer conn.Close()

			isSigningRequired := conn.session.IsSigningRequired()
			if !conn.session.IsAuthenticated() {
				log.Printf("[-] Login failed on %s\n", host)
				continue
			}

			targetInfo := conn.GetTargetInfo()
			hostResult += utils.SPrintHostInfo(host, targetInfo.GuessedOSVersion, targetInfo.DnsComputerName, targetInfo.DnsDomainName, isSigningRequired, false)
			hostResult += fmt.Sprintf("%-16s %-16s %-16s\n", "Share", "Permissions", "Decription")
			hostResult += fmt.Sprintf("%-16s %-16s %-16s\n", strings.Repeat("-", 5), strings.Repeat("-", 11), strings.Repeat("-", 10))

			shares, err := conn.ListShares()
			if err != nil {
				log.Println(err)
				continue
			}

			for _, share := range shares {
				var permissions []string

				if slices.Contains(options.Exclude, share.Name) {
					continue
				}

				err := conn.CheckReadAccess(share.Name)
				if err == nil {
					permissions = append(permissions, "READ")
					readableShares = append(readableShares, share.Name)
				}
				if conn.CheckWriteAccess(share.Name) {
					permissions = append(permissions, "WRITE")
				}

				hostResult += fmt.Sprintf("%-16s %-16s %-16s\n", share.Name, strings.Join(permissions, ","), share.Comment)
			}

			if options.List {
				for _, share := range readableShares {
					hostResult += "\n"
					var shareListResult string

					if slices.Contains(options.Exclude, share) {
						continue
					}

					files, err := conn.ListShare(share)
					if err != nil {
						log.Printf("Failed to list share %s\\%s: %s\n", conn.host, share, err)
					}

					shareListResult += fmt.Sprintf("Listing share %s\\%s\n", host, share)
					shareListResult += utils.SprintFilesExt(files)

					hostResult += shareListResult
				}
			}
			logger.Info(hostResult)
			if options.Output {
				err := options.Writer.Write(hostResult, options.File)
				if err != nil {
					log.Println(err)
				}
			}
		}
	}
}
