package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/term"
)

// PasswordEnv is the environment variable a password can come from, which
// keeps it out of the process list and the shell history.
const PasswordEnv = "SHAREFINDER_PASSWORD"

// parseAESKey decodes a Kerberos AES key given in hex: 32 characters for
// AES128, 64 for AES256.
func parseAESKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("--aes-key is not hex: %w", err)
	}
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("--aes-key must be 32 (AES128) or 64 (AES256) hex characters")
	}
	return key, nil
}

// kerberosKey parses --aes-key, which only Kerberos (-k) uses.
func kerberosKey(aesKey string, kerberos bool) ([]byte, error) {
	if aesKey == "" {
		return nil, nil
	}
	if !kerberos {
		return nil, errors.New("--aes-key is a Kerberos key: add -k")
	}
	return parseAESKey(aesKey)
}

// secretSource is where a password can come from besides -p.
type secretSource struct {
	getenv func(string) string
	isTTY  func() bool                        // stdin is a terminal
	prompt func(label string) (string, error) // reads a password without echo
}

// terminalSecrets prompts on w and reads the password with readPassword.
func terminalSecrets(w io.Writer, readPassword func() ([]byte, error)) secretSource {
	return secretSource{
		getenv: os.Getenv,
		isTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		prompt: func(label string) (string, error) {
			fmt.Fprint(w, label)
			password, err := readPassword()
			fmt.Fprintln(w) // the Enter key is not echoed
			return string(password), err
		},
	}
}

// resolvePassword picks the password: -p when given, even empty; none when a
// hash, an AES key or (with Kerberos) a ccache authenticates instead;
// SHAREFINDER_PASSWORD; a prompt when stdin is a terminal; else an empty
// password.
func resolvePassword(flagValue string, flagSet bool, hash, aesKey string, kerberos bool, src secretSource) (string, error) {
	switch {
	case flagSet:
		return flagValue, nil
	case hash != "" || aesKey != "" || (kerberos && src.getenv("KRB5CCNAME") != ""):
		return "", nil
	}
	if password := src.getenv(PasswordEnv); password != "" {
		return password, nil
	}
	if !src.isTTY() {
		logger.Debugf("No password given and stdin is not a terminal: logging on with an empty password (set -p or %s)", PasswordEnv)
		return "", nil
	}
	password, err := src.prompt("Password: ")
	if err != nil {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	return password, nil
}

// Password resolves the password of username for auth, hunt and matrix; see
// resolvePassword. The prompt goes to stderr.
func Password(username, flagValue string, flagSet bool, hash, aesKey string, kerberos bool) (string, error) {
	src := terminalSecrets(os.Stderr, func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) })
	label := src.prompt
	src.prompt = func(string) (string, error) { return label(fmt.Sprintf("Password for %s: ", username)) }
	return resolvePassword(flagValue, flagSet, hash, aesKey, kerberos, src)
}
