package common

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func RunAsDaemon() bool {
	if os.Getenv("GERO_DAEMON") == "1" {
		return true
	}
	return false
}

func StartDaemon(args []string) {
	execPath, err := os.Executable()
	if err != nil {
		ErrorLogger.Printf("Error getting executable path: %v", err)
		os.Exit(1)
	}

	cmd := exec.Command(execPath, args...)
	cmd.Env = append(os.Environ(), "GERO_DAEMON=1")

	// Initialize daemon logging
	stdout, stderr := InitDaemonLogging()

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Start()
	if err != nil {
		ErrorLogger.Printf("Error starting daemon: %v", err)
		os.Exit(1)
	}

	// Create PID file
	pidDir := filepath.Join(os.Getenv("HOME"), ".gero", "run")
	err = os.MkdirAll(pidDir, 0755)
	if err != nil {
		ErrorLogger.Printf("Error creating PID directory: %v", err)
		os.Exit(1)
	}

	pidFile := filepath.Join(pidDir, "gero.pid")
	err = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	if err != nil {
		ErrorLogger.Printf("Error writing PID file: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Started daemon with PID %d\n", cmd.Process.Pid)
	os.Exit(0)
}
