package cmd

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
)

// MatrixConfig holds the Kerberos flags of the matrix command, which apply to
// every user identity.
type MatrixConfig struct {
	Kerberos   bool
	DCHostname string
	DCIP       net.IP
}

// MatrixIdentities builds the identities of the matrix command from its
// flags. One account given without a secret gets SHAREFINDER_PASSWORD or a
// prompt, as in auth.
func MatrixIdentities(users, passwords, hashes, aesKeys []string, localAuth, kerberos, null, guest bool, guestUser string) ([]scanner.Identity, error) {
	if len(users) == 1 && len(passwords)+len(hashes)+len(aesKeys) == 0 {
		password, err := Password(users[0], "", false, "", "", kerberos)
		if err != nil {
			return nil, err
		}
		passwords = []string{password}
	}
	return scanner.BuildIdentities(users, passwords, hashes, aesKeys, localAuth, null, guest, guestUser)
}

// ExecuteMatrix tests every identity on each target and prints, per share,
// what each one can read and write. Each user logs on under a lockout guard
// of its own.
func ExecuteMatrix(ctx context.Context, s *scanner.Scanner, target string, ids []scanner.Identity, k MatrixConfig) error {
	logger.Warn("Executing matrix module")

	if s.Options.List || s.Options.Recurse {
		return errors.New("matrix checks permissions only: --list and --recurse do not apply")
	}
	if s.Options.Resume != nil {
		return errors.New("--resume continues scans of one identity: it cannot be combined with matrix")
	}
	if k.Kerberos && k.DCHostname == "" {
		return errors.New("--kerberos can't be used without --dc-hostname")
	}
	s.Options.Kerberos, s.Options.DCHostname = k.Kerberos, k.DCHostname
	if k.DCIP != nil {
		s.Options.DomainController = k.DCIP
	}
	for i := range ids {
		if ids[i].Mode != scanner.AuthUser {
			continue
		}
		if len(ids[i].AESKey) > 0 && !s.Options.Kerberos {
			return errors.New("--aes-key is a Kerberos key: add -k")
		}
		ids[i].Guard = scanner.NewAuthGuard(s.Options.AuthGuard.Max())
	}
	s.Options.Matrix = ids

	var labels []string
	for _, id := range ids {
		labels = append(labels, id.Label)
	}
	logger.Warnf("Testing %s on every host", strings.Join(labels, ", "))

	produce, err := loadTargets(s, target)
	if err != nil {
		return err
	}
	return runScan(ctx, s, "matrix", produce)
}
