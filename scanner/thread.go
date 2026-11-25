package scanner

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/utils"
)

func enumerateHost(ctx context.Context, host DNHost, options *Options) (Host, error) {
	var hostResult Host
	var shareResult []Share

	// get an SMB connection with NTLM authentication method
	logger.Debugf("Trying to establish SMB connection to %s (%s)", host.Address(), host.Hostname)
	conn, err := NewSMBConnection(ctx, host, options)
	if err != nil {
		return hostResult, err
	}
	defer conn.Close()

	// check if message signing is required
	isSigningRequired := conn.session.IsSigningRequired()
	if !conn.session.IsAuthenticated() {
		return hostResult, fmt.Errorf("not authenticated status on host %s after successful connection", host)
	}
	logger.Debugf("Successfully established SMB connection to %s (%s)", host.Address(), host.Hostname)

	// get base info about connected target
	targetInfo := conn.GetTargetInfo()
	hostResult.IP = host.Address()
	hostResult.Time = time.Now()
	hostResult.Version = "unknown"
	if targetInfo != nil {
		if targetInfo.GuessedOSVersion != "" {
			hostResult.Version = targetInfo.GuessedOSVersion
		}
		hostResult.Hostname = targetInfo.NBComputerName
		hostResult.Domain = targetInfo.DnsDomainName
	} else {
		// Kerberos auth doesn't provide NTLM target info
		hostResult.Hostname = host.Hostname
		hostResult.Domain = options.Domain
	}
	hostResult.Signing = isSigningRequired
	hostResult.Session = conn.SessionType
	if !options.NullSession {
		isAdmin, adminErr := conn.CheckLocalAdmin()
		if adminErr != nil {
			// Access-denied is the common, expected case for non-admin sessions; keep it debug-only.
			logger.Debugf("Failed to determine local admin rights on %s: %v", host.Address(), adminErr)
		} else {
			hostResult.Admin = &isAdmin
			if isAdmin {
				version, versionErr := conn.DetectWindowsVersion(hostResult.Version)
				if versionErr != nil {
					logger.Debugf("Failed to query registry version on %s: %v", host.Address(), versionErr)
				} else {
					hostResult.Version = version
				}
			}
		}
	}

	// get a list of shares
	logger.Debugf("Trying to list shares on %s (%s)", host.Address(), host.Hostname)
	shares, err := conn.GetSharesList()
	if err != nil {
		return hostResult, err
	}
	logger.Debugf("Successfully listed shares on %s (%s)", host.Address(), host.Hostname)

	// get permissions on shares
	for _, share := range shares {
		if ctx.Err() != nil {
			break
		}
		// check if share is in exclude list
		if slices.Contains(options.Exclude, share.Name) {
			continue
		}

		var singleShare Share
		singleShare.ShareName = share.Name
		singleShare.Description = share.Comment
		singleShare.TypeID = share.TypeId

		// check read and write access
		err := conn.CheckReadAccess(share.Name)
		if err == nil {
			singleShare.ReadPermission = true
		}
		// only disk shares hold files; a test file on a print queue is a print job
		if isDiskShare(share.TypeId) {
			labels := conn.CheckWriteAccess(share.Name, options.WriteCheck)
			singleShare.WritePermission = len(labels) > 0
			singleShare.WriteAccess = strings.Join(labels, ",")
		}

		shareResult = append(shareResult, singleShare)
	}

	// list share if such option is specified
	if options.List {
		limits := ListLimits{MaxDepth: options.Depth, FollowLinks: options.FollowLinks, MaxFiles: options.MaxFiles}
		for i := 0; i < len(shareResult); i++ {
			if ctx.Err() != nil {
				break
			}
			// skip share if no read permission
			if !shareResult[i].ReadPermission {
				continue
			}
			listShare(ctx, conn, &shareResult[i], limits, options.Recurse)
		}
	}
	hostResult.Shares = append(hostResult.Shares, shareResult...)
	return hostResult, nil
}

// listShare lists a readable share within limits into share.Files (the root)
// and share.Directories (each subdirectory, pre-order).
func listShare(ctx context.Context, conn *Connection, share *Share, limits ListLimits, recurse bool) {
	emit := func(dir smb.SharedFile, depth int, entries []smb.SharedFile) {
		files := listingFiles(entries)
		if depth == 0 {
			share.Files = files
			return
		}
		lastWrite := utils.ConvertToUnixTimestamp(dir.LastWriteTime)
		share.Directories = append(share.Directories, *NewDirectory(dir.FullPath, dir.Size, lastWrite, files))
	}
	onErr := func(dir string, err error) {
		logger.Warnf("Failed to list directory %s\\%s\\%s: %v", conn.host, share.ShareName, dir, err)
	}

	stats, err := conn.WalkShare(ctx, share.ShareName, limits, recurse, emit, onErr)
	if err != nil && ctx.Err() == nil {
		logger.Warnf("Failed to list share %s\\%s: %v", conn.host, share.ShareName, err)
	}
	share.Truncated = stats.Truncated
	if stats.Truncated {
		logger.Warnf("\\\\%s\\%s: listing truncated at %d entries (--max-files)", conn.host, share.ShareName, limits.MaxFiles)
	}
	if stats.DepthLimited {
		logger.Warnf("\\\\%s\\%s: directories deeper than --depth %d were not listed", conn.host, share.ShareName, limits.MaxDepth)
	}
}

// listingFiles converts directory entries, directories first. Symlinks and
// junctions, directories or not, are typed "link".
func listingFiles(entries []smb.SharedFile) []File {
	files := make([]File, 0, len(entries))
	for _, dirsFirst := range []bool{true, false} {
		for _, entry := range entries {
			if entry.IsDir != dirsFirst {
				continue
			}
			fileType := "file"
			if entry.IsDir {
				fileType = "dir"
			}
			if entry.IsJunction {
				fileType = "link"
			}
			lastWrite := utils.ConvertToUnixTimestamp(entry.LastWriteTime)
			files = append(files, *NewFile(fileType, entry.Name, utils.GetFilePath(entry.FullPath), entry.Size, lastWrite))
		}
	}
	return files
}

// scanHost enumerates one target, prints its results and writes them to the
// output files. After cancellation the partial results are still written, but
// per-host errors, which then only reflect the closed connections, are not
// reported.
func (s *Scanner) scanHost(ctx context.Context, host DNHost) {
	options := s.Options

	// resolve hostnames, apply --exclude-hosts and skip duplicates
	host, ok, err := s.resolveTarget(ctx, host)
	if err != nil {
		if ctx.Err() == nil {
			logger.Error(err)
		}
		return
	}
	if !ok {
		logger.Debugf("Skipping %s: excluded or already scanned", host.Address())
		return
	}

	// enumerate the host. Will receive the Host struct or an error
	hostResult, enumErr := enumerateHost(ctx, host, options)

	// failed on authentication
	if hostResult.IP == "" {
		if ctx.Err() == nil {
			logger.Error(fmt.Errorf("error during authentication on %s: %v", host.Address(), enumErr))
		}
		return
	}

	// format and print results on enumerated host
	printResult := SprintHostLine(hostResult)
	if len(hostResult.Shares) > 0 {
		printResult += SprintHost(hostResult, options.Exclude)

		if options.List {
			printResult += SprintShares(hostResult, options.Exclude)
		}
	}
	logger.Info(printResult)

	// write results to a file if such option is specified
	if options.FileTXT != nil {
		logger.Debugf("Writing the results in raw format to %s", options.OutputRawFileName)
		if err := options.Writer.Write(printResult, options.FileTXT); err != nil {
			logger.Error(err)
		}
	}
	if options.FileXML != nil {
		logger.Debugf("Writing the results in XML format to %s", options.OutputXMLFileName)
		if err := options.Writer.WriteXMLHost(hostResult, options.FileXML); err != nil {
			logger.Error(err)
		}
	}

	// got an error during shares enumeration
	if enumErr != nil && ctx.Err() == nil {
		logger.Error(fmt.Errorf("error during shares enumeration on %s: %v", host.Address(), enumErr))
	}
}
