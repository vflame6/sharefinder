package scanner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/utils"
)

// Identity is one way of logging on that the matrix command tests.
type Identity struct {
	Label     string // column label: null, guest, the user name (DOMAIN\user when two collide)
	Mode      AuthMode
	Username  string
	Password  string
	Domain    string
	Hash      []byte
	AESKey    []byte
	LocalAuth bool
	// Guard is the user's own lockout guard: a wrong password for one user
	// is sent once and stops the scan, whatever the other users do
	Guard *AuthGuard
}

// Name is the identity as records name it: null, guest, DOMAIN\user or user.
func (id Identity) Name() string {
	switch id.Mode {
	case AuthNull:
		return "null"
	case AuthGuest:
		return "guest"
	}
	if id.Domain != "" && !id.LocalAuth {
		return id.Domain + `\` + id.Username
	}
	return id.Username
}

// options returns a copy of o that logs on as id.
func (id Identity) options(o *Options) *Options {
	c := *o
	c.Mode, c.Username, c.Password, c.Domain = id.Mode, id.Username, id.Password, id.Domain
	c.HashBytes, c.AESKey, c.LocalAuth = id.Hash, id.AESKey, id.LocalAuth
	c.NullSession = id.Mode == AuthNull
	c.Kerberos = o.Kerberos && id.Mode == AuthUser
	c.AuthGuard = id.Guard
	return &c
}

// BuildIdentities lists what the matrix tests: a null session, a guest
// session (as guestUser, or a made-up user), then each user. -p, -H or
// --aes-key values pair with -u by position; only one kind may be given.
func BuildIdentities(users, passwords, hashes, aesKeys []string, localAuth, null, guest bool, guestUser string) ([]Identity, error) {
	var ids []Identity
	if null {
		ids = append(ids, Identity{Label: "null", Mode: AuthNull})
	}
	if guest {
		if guestUser == "" {
			guestUser = "anonymous_" + utils.RandSeq(8)
		}
		ids = append(ids, Identity{Label: "guest", Mode: AuthGuest, Username: guestUser})
	}

	var secrets []string
	var kind string
	for _, given := range []struct {
		values []string
		flag   string
	}{{passwords, "-p"}, {hashes, "-H"}, {aesKeys, "--aes-key"}} {
		if len(given.values) == 0 {
			continue
		}
		if kind != "" {
			return nil, fmt.Errorf("%s and %s cannot be mixed: give one kind of secret for every -u", kind, given.flag)
		}
		secrets, kind = given.values, given.flag
	}
	switch {
	case len(users) > 0 && kind == "":
		return nil, errors.New("give -p, -H or --aes-key for each -u")
	case len(users) != len(secrets):
		return nil, fmt.Errorf("%d -u but %d %s: each -u needs its own", len(users), len(secrets), cmpOr(kind, "secret"))
	}

	for i, user := range users {
		id := Identity{Mode: AuthUser, LocalAuth: localAuth, Username: user}
		if !localAuth {
			domain, name, ok := strings.Cut(user, `\`)
			if !ok || domain == "" || name == "" {
				return nil, fmt.Errorf("invalid username %q: use DOMAIN\\username, or --local-auth", user)
			}
			id.Domain, id.Username = domain, name
		}
		switch kind {
		case "-p":
			id.Password = secrets[i]
		case "-H":
			hash, err := hex.DecodeString(secrets[i])
			if err != nil {
				return nil, fmt.Errorf("-H for %s is not hex: %w", user, err)
			}
			id.Hash = hash
		case "--aes-key":
			key, err := hex.DecodeString(secrets[i])
			if err != nil || (len(key) != 16 && len(key) != 32) {
				return nil, fmt.Errorf("--aes-key for %s must be 32 or 64 hex characters", user)
			}
			id.AESKey = key
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, errors.New("nothing to test: give -u, or keep --null or --guest")
	}

	// a user is labelled by name, or by DOMAIN\name when two users share it
	names := map[string]int{}
	for _, id := range ids {
		if id.Mode == AuthUser {
			names[strings.ToLower(id.Username)]++
		}
	}
	for i := range ids {
		if ids[i].Mode == AuthUser {
			ids[i].Label = ids[i].Username
			if names[strings.ToLower(ids[i].Username)] > 1 {
				ids[i].Label = ids[i].Name()
			}
		}
	}
	return ids, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// MatrixCell is what one identity can do on one share.
type MatrixCell string

const (
	CellReadWrite MatrixCell = "RW"
	CellRead      MatrixCell = "R"
	CellWrite     MatrixCell = "W"
	CellNone      MatrixCell = "-" // logged on, no access
	CellFailed    MatrixCell = "x" // the logon was refused or failed
)

func shareCell(s Share) MatrixCell {
	switch {
	case s.ReadPermission && s.WritePermission:
		return CellReadWrite
	case s.ReadPermission:
		return CellRead
	case s.WritePermission:
		return CellWrite
	}
	return CellNone
}

// FormatMatrixRow is one share's line of the matrix: the share, then
// label:cell for each identity.
func FormatMatrixRow(share string, labels []string, cells []MatrixCell) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-16s", printable(share))
	for i, label := range labels {
		b.WriteString("  " + printable(label) + ":" + string(cells[i]))
	}
	return b.String()
}

// matrixHost logs on to host as each identity of the matrix, checks every
// share any of them can list (an identity may reach a share by name that it
// cannot list), and prints one row per share. Each identity's view also
// goes to the outputs, as its own host and share records.
func (s *Scanner) matrixHost(ctx context.Context, host DNHost) {
	o := s.Options
	ids := o.Matrix
	sink := s.sink()

	conns := make([]*Connection, len(ids))
	var union []mssrvs.NetShare
	listed := make(map[string]bool)
	reached := false
	for i, id := range ids {
		conn, err := NewSMBConnection(ctx, host, id.options(o))
		if err != nil {
			stage := classify(err)
			// a host that does not answer, or does not speak SMB2, fails the
			// same way for every identity: report it once
			if (stage == StageConnect && !reached) || stage == StageNegotiate {
				if stage == StageNegotiate {
					s.Stats.Reachable.Add(1)
					s.Stats.Failed.Add(1)
				}
				if ctx.Err() == nil {
					reportHostError(host.Address(), err)
				}
				return
			}
			reached = true
			if ctx.Err() == nil {
				var stageErr *StageError
				reason := err
				if errors.As(err, &stageErr) {
					reason = stageErr.Err
				}
				logger.Warnf("[-] %s: %s failed as %s: %v", host.Address(), stage, printable(id.Label), reason)
			}
			continue
		}
		defer conn.Close()
		reached = true
		conns[i] = conn
		shares, err := conn.GetSharesList()
		if err != nil {
			logger.Debugf("%s: %s cannot list the shares: %v", host.Address(), id.Label, err)
			continue
		}
		for _, share := range shares {
			if key := strings.ToLower(share.Name); !listed[key] {
				listed[key] = true
				union = append(union, share)
			}
		}
	}
	if reached {
		s.Stats.Reachable.Add(1)
	}
	// stopped (Ctrl+C, the lockout guard): what was not checked would show as
	// no access, so the host is not reported at all
	if ctx.Err() != nil {
		return
	}

	// the host's facts from the most privileged session: a user, else the
	// guest, else the null session
	pick := -1
	for _, mode := range []AuthMode{AuthUser, AuthGuest, AuthNull} {
		for i, id := range ids {
			if pick < 0 && conns[i] != nil && id.Mode == mode {
				pick = i
			}
		}
	}
	if pick < 0 {
		s.Stats.Failed.Add(1)
		return
	}
	s.Stats.Authenticated.Add(1)
	h := describeHost(conns[pick], host, ids[pick].options(o))
	h.Admin = nil // differs per identity

	views := make([][]Share, len(ids))
	for i := range ids {
		if conns[i] != nil {
			views[i] = checkShares(ctx, conns[i], union, ids[i].options(o))
		}
	}
	if ctx.Err() != nil {
		return
	}

	// the matrix
	var labels []string
	for _, id := range ids {
		labels = append(labels, id.Label)
	}
	var block strings.Builder
	block.WriteString(SprintHostLine(*h) + "\n")
	for _, share := range union {
		if slices.Contains(o.Exclude, share.Name) {
			continue
		}
		cells := make([]MatrixCell, len(ids))
		for i := range ids {
			cells[i] = CellFailed
			if conns[i] != nil {
				cells[i] = CellNone
				for _, checked := range views[i] {
					if strings.EqualFold(checked.ShareName, share.Name) {
						cells[i] = shareCell(checked)
					}
				}
			}
		}
		block.WriteString(FormatMatrixRow(share.Name, labels, cells) + "\n")
	}
	s.printMatrix(block.String())

	// each identity's view to the outputs
	var declared []string
	for _, share := range union {
		if !slices.Contains(o.Exclude, share.Name) {
			declared = append(declared, share.Name)
		}
	}
	for i, id := range ids {
		if conns[i] == nil {
			continue
		}
		view := *h
		view.Identity, view.Session, view.Shares, view.Declared = id.Name(), conns[i].SessionType, views[i], declared
		sink.HostEnumerated(&view)
		for j := range view.Shares {
			sink.ShareFinished(&view, &view.Shares[j])
			s.Stats.Shares.Add(1)
		}
		sink.HostFinished(&view)
	}
}

// printMatrix prints a host's matrix on stdout and, with -o, to the text file.
func (s *Scanner) printMatrix(block string) {
	s.matrixMu.Lock()
	defer s.matrixMu.Unlock()
	logger.Info(block)
	if f := s.Options.FileTXT; f != nil {
		if _, err := io.WriteString(f, block+"\n"); err != nil {
			logger.Error(fmt.Errorf("writing text output: %w", err))
		}
	}
}
