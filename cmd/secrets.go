package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

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
	isTTY  func() bool                        // there is a terminal to ask
	prompt func(label string) (string, error) // reads a password without echo
}

// terminalSecrets prompts on w and reads the password with read.
func terminalSecrets(w io.Writer, isTTY func() bool, read func() ([]byte, error)) secretSource {
	return secretSource{
		getenv: os.Getenv,
		isTTY:  isTTY,
		prompt: func(label string) (string, error) {
			fmt.Fprint(w, label)
			password, err := read()
			fmt.Fprintln(w) // the Enter key is not echoed
			return string(password), err
		},
	}
}

// interruptibleRead runs read, a password read with the echo off, so that
// Ctrl+C restores the terminal and ends the program (130) instead of being
// swallowed or leaving the echo off. Nothing has been created yet.
func interruptibleRead(read func() ([]byte, error), restore func(), interrupt <-chan os.Signal, exit func(int)) ([]byte, error) {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-interrupt:
			restore()
			exit(130)
		case <-done:
		}
	}()
	return read()
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
		// an empty password would count a failed logon against the account
		// on every unattended run (cron, sudo dropping the variable, ssh)
		return "", fmt.Errorf("no password: give -p, -H, --aes-key or %s, or run on a terminal to be asked (-p '' tests an empty password)", PasswordEnv)
	}
	password, err := src.prompt("Password: ")
	if err != nil {
		return "", fmt.Errorf("reading the password: %w", err)
	}
	return password, nil
}

// Password resolves the password of username for auth, hunt and matrix; see
// resolvePassword. The prompt uses the controlling terminal (/dev/tty), so
// redirected stdin or stderr do not hide it, else stdin and stderr.
func Password(username, flagValue string, flagSet bool, hash, aesKey string, kerberos bool) (string, error) {
	in, out := os.Stdin, io.Writer(os.Stderr)
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		in, out = tty, tty
	}
	fd := int(in.Fd())
	read := func() ([]byte, error) {
		state, err := term.GetState(fd)
		if err != nil {
			return nil, err
		}
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
		defer signal.Stop(interrupt)
		restore := func() {
			_ = term.Restore(fd, state)
			fmt.Fprintln(out)
		}
		return interruptibleRead(func() ([]byte, error) { return term.ReadPassword(fd) }, restore, interrupt, os.Exit)
	}
	src := terminalSecrets(out, func() bool { return term.IsTerminal(fd) }, read)
	label := src.prompt
	src.prompt = func(string) (string, error) { return label(fmt.Sprintf("Password for %s: ", username)) }
	return resolvePassword(flagValue, flagSet, hash, aesKey, kerberos, src)
}
