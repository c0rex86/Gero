package common

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
	DebugLogger *log.Logger
	IsVerbose   bool
)

func InitLogging(verbose bool) {
	IsVerbose = verbose

	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	if IsVerbose {
		DebugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		DebugLogger = log.New(io.Discard, "", 0)
	}
}

func InitDaemonLogging() (*os.File, *os.File) {
	logDir := filepath.Join(os.Getenv("HOME"), ".gero", "logs")
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		fmt.Println("Error creating log directory:", err)
		os.Exit(1)
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	stdoutPath := filepath.Join(logDir, fmt.Sprintf("gero_%s.log", timestamp))
	stderrPath := filepath.Join(logDir, fmt.Sprintf("gero_%s.err", timestamp))

	stdoutLatestPath := filepath.Join(logDir, "gero_latest.log")
	stderrLatestPath := filepath.Join(logDir, "gero_latest.err")

	os.Remove(stdoutLatestPath)
	os.Remove(stderrLatestPath)

	stdout, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Error opening log file:", err)
		os.Exit(1)
	}

	if err := os.Symlink(stdoutPath, stdoutLatestPath); err != nil {
		fmt.Printf("Warning: could not create symlink to latest log: %v\n", err)
	}

	stderr, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Error opening error log file:", err)
		os.Exit(1)
	}

	if err := os.Symlink(stderrPath, stderrLatestPath); err != nil {
		fmt.Printf("Warning: could not create symlink to latest error log: %v\n", err)
	}

	InfoLogger = log.New(stdout, "INFO: ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	DebugLogger = log.New(stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)

	return stdout, stderr
}
