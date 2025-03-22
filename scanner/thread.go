package scanner

import (
	"fmt"
	"github.com/vflame6/sharefinder/logger"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
)

func scanThread(s <-chan bool, wg *sync.WaitGroup, targets, results chan net.IP, options *Options) {
	defer wg.Done()
	for {
		select {
		case <-s:
			return
		default:
			host, ok := <-targets
			if !ok {
				return
			}
			address := host.String() + ":445"
			conn, err := net.DialTimeout("tcp", address, options.Timeout)
			if err != nil {
				continue
			}
			_ = conn.Close()
			results <- host
		}
	}
}

func enumerateHost(host string, options *Options) (string, error) {
	var hostResult string
	var readableShares []string

	conn, err := NewNTLMConnection(host, options.Username, options.Password, options.Domain, options.Timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	isSigningRequired := conn.session.IsSigningRequired()
	if !conn.session.IsAuthenticated() {
		return "", err
	}

	targetInfo := conn.GetTargetInfo()
	hostResult += SPrintHostInfo(host, targetInfo.GuessedOSVersion, targetInfo.NBComputerName, targetInfo.DnsDomainName, isSigningRequired, false)
	hostResult += fmt.Sprintf("%-16s %-16s %-16s\n", "Share", "Permissions", "Decription")
	hostResult += fmt.Sprintf("%-16s %-16s %-16s\n", strings.Repeat("-", 5), strings.Repeat("-", 11), strings.Repeat("-", 10))

	shares, err := conn.ListShares()
	if err != nil {
		return "", err
	}

	for _, share := range shares {
		var permissions []string

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
			shareListResult += SprintFilesExt(files)

			hostResult += shareListResult
		}
	}
	return hostResult, nil
}

func authThread(s <-chan bool, options *Options, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-s:
			return
		default:
			host, ok := <-options.Target
			if !ok {
				return
			}

			hostResult, err := enumerateHost(host, options)
			if err != nil {
				logger.Info(fmt.Sprintf("[-] %s: %s", host, err.Error()))
				continue
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
