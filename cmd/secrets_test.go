package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseAESKey(t *testing.T) {
	aes128 := "00112233445566778899aabbccddeeff"
	aes256 := aes128 + aes128
	for _, tc := range []struct {
		in   string
		size int // bytes, 0 for an error
	}{
		{aes128, 16},
		{aes256, 32},
		{"00112233445566778899AABBCCDDEEFF", 16},
		{aes128[:30], 0},                        // too short
		{aes128 + "0011223344", 0},              // neither 128 nor 256 bits
		{"zz112233445566778899aabbccddeeff", 0}, // not hex
		{"", 0},
	} {
		key, err := parseAESKey(tc.in)
		switch {
		case tc.size == 0 && err == nil:
			t.Errorf("parseAESKey(%q) accepted a bad key", tc.in)
		case tc.size != 0 && (err != nil || len(key) != tc.size):
			t.Errorf("parseAESKey(%q) = %d bytes, %v; want %d bytes", tc.in, len(key), err, tc.size)
		}
	}
}

func TestResolvePassword(t *testing.T) {
	type env map[string]string
	tests := []struct {
		name      string
		flag      string
		flagSet   bool
		hash, aes string
		kerberos  bool
		env       env
		tty       bool
		want      string
		prompted  bool
	}{
		{name: "-p wins, also when empty", flag: "", flagSet: true, env: env{"SHAREFINDER_PASSWORD": "fromenv"}, tty: true, want: ""},
		{name: "-p value", flag: "Secret1", flagSet: true, tty: true, want: "Secret1"},
		{name: "environment", env: env{"SHAREFINDER_PASSWORD": "fromenv"}, tty: true, want: "fromenv"},
		{name: "a hash needs no password, also with the variable set", hash: "aad3b435b51404ee", env: env{"SHAREFINDER_PASSWORD": "fromenv"}, tty: true, want: ""},
		{name: "an AES key needs no password", aes: "00112233445566778899aabbccddeeff", kerberos: true, tty: true, want: ""},
		{name: "a Kerberos ccache needs no password", kerberos: true, env: env{"KRB5CCNAME": "/tmp/krb5cc_1000"}, tty: true, want: ""},
		{name: "a ccache does not apply to NTLM", env: env{"KRB5CCNAME": "/tmp/krb5cc_1000"}, tty: true, want: "typed", prompted: true},
		{name: "prompt on a terminal", tty: true, want: "typed", prompted: true},
		{name: "no terminal: empty password", tty: false, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompted := false
			src := secretSource{
				getenv: func(k string) string { return tt.env[k] },
				isTTY:  func() bool { return tt.tty },
				prompt: func(string) (string, error) { prompted = true; return "typed", nil },
			}
			got, err := resolvePassword(tt.flag, tt.flagSet, tt.hash, tt.aes, tt.kerberos, src)
			if err != nil || got != tt.want || prompted != tt.prompted {
				t.Fatalf("resolvePassword = %q, %v (prompted %v); want %q (prompted %v)", got, err, prompted, tt.want, tt.prompted)
			}
		})
	}

	failing := secretSource{
		getenv: func(string) string { return "" },
		isTTY:  func() bool { return true },
		prompt: func(string) (string, error) { return "", errors.New("read failed") },
	}
	if _, err := resolvePassword("", false, "", "", false, failing); err == nil {
		t.Fatal("a failed prompt is an error, not an empty password")
	}
}

func TestExecuteAuth_AESKey(t *testing.T) {
	key := "00112233445566778899aabbccddeeff"
	for name, tc := range map[string]struct {
		aes      string
		kerberos bool
		want     string
	}{
		"needs -k":      {aes: key, want: "-k"},
		"must be a key": {aes: "abcd", kerberos: true, want: "--aes-key"},
	} {
		s, err := CreateScanner(validConfig())
		if err != nil {
			t.Fatal(err)
		}
		err = ExecuteAuth(context.Background(), s, "192.0.2.1", `CORP\jdoe`, "", "", tc.aes, false, tc.kerberos, "dc01", nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ExecuteAuth = %v, want an error naming %s", name, err, tc.want)
		}
	}

	s, err := CreateScanner(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.Options.Discovery.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // no scan: only the options are of interest
	_ = ExecuteAuth(ctx, s, "192.0.2.1", `CORP\jdoe`, "", "", key, false, true, "dc01", nil)
	if len(s.Options.AESKey) != 16 || s.Options.Password != "" {
		t.Fatalf("AES key %x, password %q", s.Options.AESKey, s.Options.Password)
	}
}

func TestPromptLabel(t *testing.T) {
	var buf bytes.Buffer
	src := terminalSecrets(&buf, func() ([]byte, error) { return []byte("typed"), nil })
	got, err := src.prompt(`Password for CORP\jdoe: `)
	if err != nil || got != "typed" {
		t.Fatalf("prompt = %q, %v", got, err)
	}
	if buf.String() != "Password for CORP\\jdoe: \n" {
		t.Fatalf("the prompt goes to the terminal, the typed password does not: %q", buf.String())
	}
}
