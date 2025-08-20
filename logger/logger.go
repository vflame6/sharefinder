package logger

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

// CustomLogger provides formatted logging with multi-line indentation
type CustomLogger struct {
	logger  *log.Logger
	mutex   sync.Mutex
	Debug   bool
	Quiet   bool
	Padding string
}

// Log is a global instance of CustomLogger
var Log = NewCustomLogger()

// NewCustomLogger initializes a new logger instance
func NewCustomLogger() *CustomLogger {
	return &CustomLogger{
		logger:  log.Default(),
		Padding: strings.Repeat(" ", 20),
	}
}

// SetLoggerOptions configures debug and quiet parameters
func SetLoggerOptions(debug, quiet bool) error {
	if debug == true && quiet == true {
		return fmt.Errorf("debug mode can not be used with quiet mode")
	}

	Log.Debug = debug
	Log.Quiet = quiet
	return nil
}

// LogString is a function to make basic logs
func LogString(s string) {
	// split lines to determine if several lines are needed
	lines := strings.Split(s, "\n")
	if len(lines) > 1 {
		// print the first one with timestamp and the others with padding
		firstLine := lines[0]
		Log.logger.Println(firstLine)
		for _, line := range lines[1:] {
			fmt.Println(Log.Padding + line)
		}
	} else {
		Log.logger.Println(s)
	}
}

// LogDebugString is a function to make debug logs
func LogDebugString(s string) {
	Log.logger.Println("[DEBUG] " + s)
}

// LogErrorString is a function to make debug logs
func LogErrorString(s string) {
	Log.logger.Println("[ERROR] " + s)
}

// Info logs a formatted multi-line message
// Info logs are used to print necessary results
func Info(msg string) {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()

	LogString(msg)
}

// Infof works like Info with format string parsing
// Infof logs are used to print necessary results
func Infof(format string, args ...interface{}) {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()

	msg := fmt.Sprintf(format, args...)
	LogString(msg)
}

// Warn logs a formatted multi-line WARN message
// Warn logs could be suppressed with --quiet option
func Warn(msg string) {
	if !Log.Quiet {
		Log.mutex.Lock()
		defer Log.mutex.Unlock()

		LogString(msg)
	}
}

// Warnf works like Warn with format string parsing
// Warnf logs could be suppressed with --quiet option
func Warnf(format string, args ...interface{}) {
	if !Log.Quiet {
		Log.mutex.Lock()
		defer Log.mutex.Unlock()

		msg := fmt.Sprintf(format, args...)
		LogString(msg)
	}
}

// Debug logs a formatted debug message
// Debug logs are suppressed if the --debug option is not specified
func Debug(msg string) {
	if Log.Debug {
		Log.mutex.Lock()
		defer Log.mutex.Unlock()

		LogDebugString(msg)
	}
}

// Debugf works like Debug with format string parsing
// Debugf logs are suppressed if the --debug option is not specified
func Debugf(format string, args ...interface{}) {
	if Log.Debug {
		Log.mutex.Lock()
		defer Log.mutex.Unlock()
		msg := fmt.Sprintf(format, args...)
		LogDebugString(msg)
	}
}

// Error logs a formatted error message and the program execution continues
// Error logs could be suppressed with --quiet option
func Error(err error) {
	if !Log.Quiet {
		Log.mutex.Lock()
		defer Log.mutex.Unlock()
		LogErrorString(err.Error())
	}
}

// Fatal logs a formatted fatal errors and shuts the program down
// Fatal logs are critical and could not be suppressed
func Fatal(err error) {
	Log.logger.Fatal(err)
}
