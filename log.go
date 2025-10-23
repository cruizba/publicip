package publicip

import (
	"log"
	"os"
)

var (
	// debug is a flag indicating whether debug logging is enabled
	debug bool
	// debugLogger is the logger instance for debug messages
	debugLogger *log.Logger
)

func init() {
	// Check if debug logging is enabled via environment variable
	if os.Getenv("PUBLIC_IP_AUTODISCOVERY_DEBUG") == "true" {
		debug = true
		// Initialize logger with timestamp and prefix
		debugLogger = log.New(os.Stderr, "[PublicIP Debug] ", log.Ldate|log.Ltime|log.Lmicroseconds)
	}
}

// logDebug logs a debug message if debug logging is enabled
func logDebug(format string, v ...interface{}) {
	if debug && debugLogger != nil {
		debugLogger.Printf(format, v...)
	}
}
