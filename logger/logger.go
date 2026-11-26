// Package logger prints sharefinder's output: results go to stdout, so they
// can be piped or redirected on their own; the banner, progress, warnings,
// errors and debug messages go to stderr.
package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/jfjallid/golog"
)

// goSmbLogPackages lists go-smb subpackages whose internal loggers are silenced
// in non-debug mode. The library logs RPC faults at Error level; for our use
// cases (e.g. DCERPC access-denied while probing local-admin rights without
// privileges) those are expected, not actionable, and clutter normal output.
var goSmbLogPackages = []string{
	"github.com/jfjallid/go-smb/smb",
	"github.com/jfjallid/go-smb/smb/compress",
	"github.com/jfjallid/go-smb/dcerpc",
	"github.com/jfjallid/go-smb/dcerpc/msrrp",
	"github.com/jfjallid/go-smb/dcerpc/msscmr",
	"github.com/jfjallid/go-smb/dcerpc/mssrvs",
	"github.com/jfjallid/go-smb/spnego",
	"github.com/jfjallid/go-smb/krb5ssp",
	"github.com/jfjallid/go-smb/ntlmssp",
	"github.com/jfjallid/go-smb/gss",
}

// CustomLogger writes results to Out and messages to Err.
type CustomLogger struct {
	Out io.Writer // results
	Err io.Writer // banner, warnings, errors, debug

	logger  *log.Logger // timestamps messages on Err in debug mode
	mutex   sync.Mutex
	Debug   bool
	Quiet   bool
	Padding string

	// status draws the progress line kept at the bottom of a terminal
	// stderr; nil when there is none
	status      func() string
	statusShown bool
}

// Log is a global instance of CustomLogger
var Log = NewCustomLogger()

// NewCustomLogger initializes a new logger instance
func NewCustomLogger() *CustomLogger {
	return &CustomLogger{
		Out:     os.Stdout,
		Err:     os.Stderr,
		logger:  log.New(os.Stderr, "", log.LstdFlags),
		Padding: strings.Repeat(" ", 20),
	}
}

// SetWriters routes results to out and every other message to errOut.
func SetWriters(out, errOut io.Writer) {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	Log.Out, Log.Err = out, errOut
	Log.logger = log.New(errOut, "", log.LstdFlags)
}

// SetLoggerOptions configures debug and quiet parameters
func SetLoggerOptions(debug, quiet bool) error {
	if debug && quiet {
		return fmt.Errorf("debug mode can not be used with quiet mode")
	}

	Log.Debug = debug
	Log.Quiet = quiet

	libLevel := golog.LevelNotice
	if !debug {
		libLevel = golog.LevelNone
	}
	for _, name := range goSmbLogPackages {
		// go-smb's own messages are diagnostics, never results
		golog.Get(name).SetLogLevel(libLevel).SetOutput(Log.Err)
	}

	return nil
}

// writeResult prints a result on Out, ending it with exactly one newline
// unless it already ends with a blank line.
func writeResult(s string) {
	if strings.HasSuffix(s, "\n\n") {
		fmt.Fprint(Log.Out, s)
	} else {
		fmt.Fprintln(Log.Out, strings.TrimSuffix(s, "\n"))
	}
}

// writeMessage prints a message on Err, timestamped in debug mode.
func writeMessage(s string) {
	if !Log.Debug {
		fmt.Fprintln(Log.Err, strings.TrimSuffix(s, "\n"))
		return
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	Log.logger.Println(lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintln(Log.Err, Log.Padding+line)
	}
}

// SetStatus keeps the line status() returns at the bottom of stderr: every
// message and result is written above it, and RedrawStatus refreshes it.
// Use it only when stderr is a terminal.
func SetStatus(status func() string) {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	Log.clearStatus()
	Log.status = status
	Log.drawStatus()
}

// RedrawStatus redraws the status line with fresh values.
func RedrawStatus() {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	if Log.status != nil {
		Log.clearStatus()
		Log.drawStatus()
	}
}

// ClearStatus removes the status line and stops drawing it.
func ClearStatus() {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	Log.clearStatus()
	Log.status = nil
}

// clearStatus erases the status line; the cursor returns to its start.
func (l *CustomLogger) clearStatus() {
	if l.statusShown {
		fmt.Fprint(l.Err, "\r\033[K")
		l.statusShown = false
	}
}

func (l *CustomLogger) drawStatus() {
	if l.status != nil {
		fmt.Fprint(l.Err, l.status())
		l.statusShown = true
	}
}

// above writes output above the status line. Callers hold the mutex.
func above(write func()) {
	Log.clearStatus()
	write()
	Log.drawStatus()
}

// Info prints a result. Results are never suppressed.
func Info(msg string) {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	above(func() { writeResult(msg) })
}

// Infof works like Info with format string parsing
func Infof(format string, args ...any) {
	Info(fmt.Sprintf(format, args...))
}

// Warn prints a status message on stderr; --quiet suppresses it.
func Warn(msg string) {
	if Log.Quiet {
		return
	}
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	above(func() { writeMessage(msg) })
}

// Warnf works like Warn with format string parsing
func Warnf(format string, args ...any) {
	Warn(fmt.Sprintf(format, args...))
}

// Debug prints a debug message on stderr when --debug is set.
func Debug(msg string) {
	if !Log.Debug {
		return
	}
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	above(func() { Log.logger.Println("[DEBUG] " + strings.TrimSpace(msg)) })
}

// Debugf works like Debug with format string parsing
func Debugf(format string, args ...any) {
	if Log.Debug {
		Debug(fmt.Sprintf(format, args...))
	}
}

// Error prints an error on stderr and the program continues; --quiet
// suppresses it.
func Error(err error) {
	if Log.Quiet {
		return
	}
	Log.mutex.Lock()
	defer Log.mutex.Unlock()
	above(func() { writeMessage("[ERROR] " + strings.TrimSpace(err.Error())) })
}

// Fatal prints an error on stderr and exits with status 1. It is never
// suppressed.
func Fatal(err error) {
	Log.mutex.Lock()
	Log.clearStatus()
	fmt.Fprintln(Log.Err, "[FATAL] "+err.Error())
	Log.mutex.Unlock()
	os.Exit(1)
}
