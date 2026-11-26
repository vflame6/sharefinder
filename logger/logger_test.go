package logger

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// useBuffers routes the logger into buffers for one test.
func useBuffers(t *testing.T, debug, quiet bool) (out, errOut *bytes.Buffer) {
	t.Helper()
	out, errOut = &bytes.Buffer{}, &bytes.Buffer{}
	prevOut, prevErr, prevDebug, prevQuiet := Log.Out, Log.Err, Log.Debug, Log.Quiet
	SetWriters(out, errOut)
	Log.Debug, Log.Quiet = debug, quiet
	t.Cleanup(func() {
		SetWriters(prevOut, prevErr)
		Log.Debug, Log.Quiet = prevDebug, prevQuiet
	})
	return out, errOut
}

func TestLoggerStreams(t *testing.T) {
	out, errOut := useBuffers(t, false, false)

	Info("[+] 10.0.0.5: result")
	Warn("Executing auth module")
	Error(errors.New("authentication failed on 10.0.0.9"))

	if got := out.String(); got != "[+] 10.0.0.5: result\n" {
		t.Errorf("stdout = %q, want only the result", got)
	}
	for _, want := range []string{"Executing auth module", "[ERROR] authentication failed on 10.0.0.9"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr lacks %q: %q", want, errOut.String())
		}
	}
	if strings.Contains(errOut.String(), "result") {
		t.Errorf("results must not go to stderr: %q", errOut.String())
	}
}

func TestLoggerDebugGoesToStderr(t *testing.T) {
	out, errOut := useBuffers(t, true, false)

	Debugf("dialing %s", "10.0.0.5")
	Info("[+] result")

	if !strings.Contains(errOut.String(), "[DEBUG] dialing 10.0.0.5") {
		t.Errorf("stderr lacks the debug line: %q", errOut.String())
	}
	if out.String() != "[+] result\n" {
		t.Errorf("stdout = %q: results stay plain on stdout in debug mode", out.String())
	}
}

func TestLoggerQuietKeepsResultsOnly(t *testing.T) {
	out, errOut := useBuffers(t, false, true)

	Warn("banner-ish warning")
	Error(errors.New("boom"))
	Info("[+] result")

	if errOut.Len() != 0 {
		t.Errorf("--quiet must silence warnings and errors, stderr = %q", errOut.String())
	}
	if out.String() != "[+] result\n" {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestLoggerMultilineResultKeepsBlankLine(t *testing.T) {
	out, _ := useBuffers(t, false, false)
	Info("[+] host\nShare  Permissions\n\n")
	if out.String() != "[+] host\nShare  Permissions\n\n" {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestLoggerStatusRedraw(t *testing.T) {
	// results and messages share one terminal, as they do interactively
	var tty bytes.Buffer
	useBuffers(t, false, false)
	SetWriters(&tty, &tty)
	n := 0
	SetStatus(func() string { n++; return fmt.Sprintf("[*] status %d", n) })
	t.Cleanup(ClearStatus)

	Info("[+] result")
	Warn("warning")
	RedrawStatus()
	ClearStatus()
	Info("after")

	const clear = "\r\033[K"
	want := "[*] status 1" + clear + "[+] result\n" + "[*] status 2" +
		clear + "warning\n" + "[*] status 3" +
		clear + "[*] status 4" +
		clear + "after\n"
	if got := tty.String(); got != want {
		t.Fatalf("terminal:\n%q\nwant\n%q", got, want)
	}
}

func TestLoggerEscapesControlCharacters(t *testing.T) {
	// a hostile server names a share so as to retitle and clear the terminal
	hostile := "Data\x1b]0;pwned\x07\x1b[2J\r"
	out, errOut := useBuffers(t, true, false)
	Info("[+] " + hostile)
	Warn("Failed to list share " + hostile)
	Error(errors.New("listing " + hostile))
	Debug("probing " + hostile)
	for name, got := range map[string]string{"stdout": out.String(), "stderr": errOut.String()} {
		if strings.ContainsAny(got, "\x1b\x07\r") {
			t.Errorf("%s carries raw control characters: %q", name, got)
		}
		if !strings.Contains(got, `Data\x1b]0;pwned\x07\x1b[2J\x0d`) {
			t.Errorf("%s must show them escaped: %q", name, got)
		}
	}
	// line breaks and tabs that the messages themselves use stay
	out.Reset()
	Info("Share\tPermissions\ndata\tREAD")
	if out.String() != "Share\tPermissions\ndata\tREAD\n" {
		t.Errorf("tabs and newlines must stay: %q", out.String())
	}
}

func TestLoggerStatusOffWritesNoControlSequences(t *testing.T) {
	out, errOut := useBuffers(t, false, false)
	RedrawStatus()
	ClearStatus()
	Info("[+] result")
	Warn("warning")
	if strings.Contains(out.String()+errOut.String(), "\033") {
		t.Fatalf("without a status line nothing but text is written: %q %q", out, errOut)
	}
}
