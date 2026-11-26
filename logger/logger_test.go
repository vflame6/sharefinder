package logger

import (
	"bytes"
	"errors"
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
