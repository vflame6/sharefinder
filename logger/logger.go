package logger

import (
	"fmt"
	"log"
	"strings"
	"sync"
)

// CustomLogger provides formatted logging with multi-line indentation
type CustomLogger struct {
	logger *log.Logger
	mutex  sync.Mutex
}

// Global instance of CustomLogger
var Log = NewCustomLogger()

// NewCustomLogger initializes a new logger instance
func NewCustomLogger() *CustomLogger {
	return &CustomLogger{
		logger: log.Default(),
	}
}

// Info logs a formatted multi-line message
func Info(msg string) {
	Log.mutex.Lock()
	defer Log.mutex.Unlock()

	lines := strings.Split(msg, "\n")
	if len(lines) > 1 {
		firstLine := lines[0]
		Log.logger.Println(firstLine)
		padding := strings.Repeat(" ", 20)
		for _, line := range lines[1:] {
			fmt.Println(padding + line)
		}
	} else {
		Log.logger.Println(msg)
	}
}
