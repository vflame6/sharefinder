package scanner

import (
	"context"
	"slices"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/utils"
)

// shareChecker tests access to one share of a connected host.
type shareChecker interface {
	CheckReadAccess(share string) error
	CheckWriteAccess(share string, mode WriteCheckMode) []string
}

// checkShares tests read and write access on every share that is not
// excluded. A share whose checks were cut short by cancellation is left out:
// the permissions it would show are not findings, only closed connections.
func checkShares(ctx context.Context, c shareChecker, shares []mssrvs.NetShare, options *Options) []Share {
	var result []Share
	for _, share := range shares {
		if ctx.Err() != nil {
			break
		}
		if slices.Contains(options.Exclude, share.Name) {
			continue
		}

		checked := Share{ShareName: share.Name, Description: share.Comment, TypeID: share.TypeId, ShareType: shareTypeName(share.TypeId)}
		checked.ReadPermission = c.CheckReadAccess(share.Name) == nil
		// only disk shares hold files; a test file on a print queue is a print job
		if isDiskShare(share.TypeId) {
			labels := c.CheckWriteAccess(share.Name, options.WriteCheck)
			checked.WritePermission = len(labels) > 0
			checked.WriteAccess = strings.Join(labels, ",")
		}
		if ctx.Err() != nil {
			break
		}
		result = append(result, checked)
	}
	return result
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
