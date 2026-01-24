package scanner

import (
	"errors"
	"fmt"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/utils"
	"slices"
	"sync"
	"time"
)

func enumerateHost(host DNHost, options *Options) (Host, error) {
	var hostResult Host
	var shareResult []Share

	// get an SMB connection with NTLM authentication method
	logger.Debugf("Trying to establish SMB connection to %s (%s)", host.IP.String(), host.Hostname)
	conn, err := NewSMBConnection(
		host,
		options.Username,
		options.Password,
		options.HashBytes,
		options.Kerberos,
		options.LocalAuth,
		options.Domain,
		options.Timeout,
		options.SmbPort,
		options.ProxyDialer,
		options.DomainController,
		options.NullSession,
	)
	if err != nil {
		return hostResult, err
	}
	defer conn.Close()

	// check if message signing is required
	isSigningRequired := conn.session.IsSigningRequired()
	if !conn.session.IsAuthenticated() {
		return hostResult, fmt.Errorf("not authenticated status on host %s after successful connection", host)
	}
	logger.Debugf("Successfully established SMB connection to %s (%s)", host.IP.String(), host.Hostname)

	// get base info about connected target
	targetInfo := conn.GetTargetInfo()
	hostResult.IP = host.IP.String()
	hostResult.Time = time.Now()
	hostResult.Version = targetInfo.GuessedOSVersion
	hostResult.Hostname = targetInfo.NBComputerName
	hostResult.Domain = targetInfo.DnsDomainName
	hostResult.Signing = isSigningRequired

	// get a list of shares
	logger.Debugf("Trying to list shares on %s (%s)", host.IP.String(), host.Hostname)
	shares, err := conn.GetSharesList()
	if err != nil {
		return hostResult, err
	}
	logger.Debugf("Successfully listed shares on %s (%s)", host.IP.String(), host.Hostname)

	// get permissions on shares
	for _, share := range shares {
		// check if share is in exclude list
		if slices.Contains(options.Exclude, share.Name) {
			continue
		}

		var singleShare Share
		singleShare.ShareName = share.Name
		singleShare.Description = share.Comment

		// check read and write access
		err := conn.CheckReadAccess(share.Name)
		if err == nil {
			singleShare.ReadPermission = true
		}
		if conn.CheckWriteAccess(share.Name) {
			singleShare.WritePermission = true
		}

		shareResult = append(shareResult, singleShare)
	}

	// list share if such option is specified
	if options.List {
		for i := 0; i < len(shareResult); i++ {
			// skip share if no read permission
			if !shareResult[i].ReadPermission {
				continue
			}

			// here we loop over all files 2 times to process directories at first and files at second
			files, err := conn.ListShare(shareResult[i].ShareName)
			if err != nil {
				logger.Warnf("Failed to list share %s\\%s: %s", conn.host, shareResult[i].ShareName, err.Error())
			}

			// loop over all files 2 times to process directories at first
			// it is done like that to make directories in the top of the output
			for _, file := range files {
				if file.IsDir {
					lastWriteTime := utils.ConvertToUnixTimestamp(file.LastWriteTime)

					fileType := "dir"

					singleFile := NewFile(fileType, file.Name, utils.GetFilePath(file.FullPath), file.Size, lastWriteTime)
					shareResult[i].Files = append(shareResult[i].Files, *singleFile)

					// list all directories recursively if such option is specified
					if options.Recurse {
						recurseDirectory, err := conn.ListDirectoryRecursively(shareResult[i].ShareName, file)
						if err != nil {
							logger.Warnf("Failed to list directory %s\\%s\\%s: %s", conn.host, shareResult[i].ShareName, file.Name, err.Error())
						}
						shareResult[i].Directories = append(shareResult[i].Directories, recurseDirectory...)
					}
				} else {
					continue
				}
			}
			// process files
			for _, file := range files {
				if !file.IsDir {
					lastWriteTime := utils.ConvertToUnixTimestamp(file.LastWriteTime)

					fileType := "file"
					if file.IsJunction {
						fileType = "link"
					}

					singleFile := NewFile(fileType, file.Name, utils.GetFilePath(file.FullPath), file.Size, lastWriteTime)
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

func smbThread(s <-chan bool, options *Options, wg *sync.WaitGroup) {
	// reduce the number of WaitGroup after returning from function
	defer wg.Done()

	for {
		select {
		case <-s:
			// stop if the stop channel is closed
			return
		default:
			// receive a target from target channel
			host, ok := <-options.Target
			if !ok {
				// stop if the target list is over
				return
			}

			// enumerate the host. Will receive the Host struct or an error
			hostResult, err := enumerateHost(host, options)

			// failed on authentication
			if hostResult.IP == "" {
				logger.Error(errors.New(fmt.Sprintf("Error during authentication on %s: %v", host.IP, err)))
				continue
			}

			// format and print results on enumerated host
			printResult := SPrintHostInfo(hostResult.IP, hostResult.Version, hostResult.Hostname, hostResult.Domain, hostResult.Signing)
			if len(hostResult.Shares) > 0 {
				printResult += SprintHost(hostResult, options.Exclude)

				if options.List {
					printResult += SprintShares(hostResult, options.Exclude)
				}
			}
			logger.Info(printResult)

			// write results to a file if such option is specified
			if options.FileTXT != nil {
				// try to write raw version
				logger.Debugf("Writing the results in raw format to %s", options.OutputRawFileName)
				err = options.Writer.Write(printResult, options.FileTXT)
				if err != nil {
					logger.Error(err)
				}
			}
			if options.FileXML != nil {
				// try to write XML version
				logger.Debugf("Writing the results in XML format to %s", options.OutputXMLFileName)
				err = options.Writer.WriteXMLHost(hostResult, options.FileXML)
				if err != nil {
					logger.Error(err)
				}
			}

			// got an error during shares enumeration
			if err != nil {
				logger.Error(errors.New(fmt.Sprintf("Error during shares enumeration on %s: %v", host.IP, err)))
				continue
			}
		}
	}
}
