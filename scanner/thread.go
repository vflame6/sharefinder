package scanner

import (
	"fmt"
	"github.com/vflame6/sharefinder/logger"
	"log"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
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
			address := host.String() + ":" + strconv.Itoa(options.SmbPort)
			conn, err := net.DialTimeout("tcp", address, options.Timeout)
			if err != nil {
				continue
			}
			_ = conn.Close()
			results <- host
		}
	}
}

func enumerateHost(host string, options *Options) (Host, error) {
	var hostResult Host
	var shareResult []Share

	conn, err := NewNTLMConnection(host, options.Username, options.Password, options.Domain, options.Timeout, options.SmbPort)
	if err != nil {
		return hostResult, err
	}
	defer conn.Close()

	isSigningRequired := conn.session.IsSigningRequired()
	if !conn.session.IsAuthenticated() {
		return hostResult, err
	}

	targetInfo := conn.GetTargetInfo()
	hostResult.IP = host
	hostResult.Time = time.Now()
	hostResult.Version = targetInfo.GuessedOSVersion
	hostResult.Hostname = targetInfo.NBComputerName
	hostResult.Domain = targetInfo.DnsDomainName
	hostResult.Signing = isSigningRequired
	// TODO implement SMBv1 check

	shares, err := conn.ListShares()
	if err != nil {
		return hostResult, err
	}

	for _, share := range shares {
		if slices.Contains(options.Exclude, share.Name) {
			continue
		}

		var singleShare Share
		singleShare.ShareName = share.Name
		singleShare.Description = share.Comment

		err := conn.CheckReadAccess(share.Name)
		if err == nil {
			singleShare.ReadPermission = true
		}
		if conn.CheckWriteAccess(share.Name) {
			singleShare.WritePermission = true
		}

		shareResult = append(shareResult, singleShare)
	}

	if options.List {
		for i := 0; i < len(shareResult); i++ {
			if !shareResult[i].ReadPermission {
				continue
			}

			// here we loop over all files 2 times to process directories at first and files at second
			files, err := conn.ListShare(shareResult[i].ShareName)
			if err != nil {
				log.Printf("Failed to list share %s\\%s: %s\n", conn.host, shareResult[i].ShareName, err)
			}
			for _, file := range files {
				if file.IsDir {
					// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
					// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
					// and divide by 10 to convert to microseconds
					lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))

					fileType := "dir"
					singleFile := NewFile(fileType, file.Name, file.Size, lastWriteTime)
					shareResult[i].Files = append(shareResult[i].Files, *singleFile)

					if options.Recurse {
						recurseDirectory, err := conn.ListDirectoryRecursively(shareResult[i].ShareName, file)
						if err != nil {
							log.Printf("Failed to list directory %s\\%s\\%s: %s\n", conn.host, shareResult[i].ShareName, file.Name, err)
						}
						shareResult[i].Directories = append(shareResult[i].Directories, recurseDirectory...)
					}
				} else {
					continue
				}
			}

			for _, file := range files {
				if !file.IsDir {
					lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))
					fileType := "file"
					if file.IsJunction {
						fileType = "link"
					}
					singleFile := NewFile(fileType, file.Name, file.Size, lastWriteTime)
					shareResult[i].Files = append(shareResult[i].Files, *singleFile)
				} else {
					continue
				}
			}
		}
	}
	hostResult.Shares = append(hostResult.Shares, shareResult...)
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

			printResult := SprintHost(hostResult, options.Exclude)
			if options.List {
				printResult += SprintShares(hostResult, options.Exclude)
			}

			logger.Info(printResult)

			if options.Output {
				err := options.Writer.Write(printResult, options.File)
				if err != nil {
					log.Println(err)
				}

				err = options.Writer.WriteXMLHost(hostResult, options.FileXML)
				if err != nil {
					log.Println(err)
				}
			}
		}
	}
}
