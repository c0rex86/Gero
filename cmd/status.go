package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/c0rex86/gero/internal/common"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check Gero status",
	Long:  `Check the status of running Gero daemon processes.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize logging
		common.InitLogging(verbose)

		// Check for PID file
		pidDir := filepath.Join(os.Getenv("HOME"), ".gero", "run")
		pidFile := filepath.Join(pidDir, "gero.pid")

		if _, err := os.Stat(pidFile); os.IsNotExist(err) {
			fmt.Println("Gero is not running")
			return
		}

		// Read PID from file
		pidBytes, err := os.ReadFile(pidFile)
		if err != nil {
			common.ErrorLogger.Printf("Error reading PID file: %v", err)
			fmt.Println("Gero status: Unknown (error reading PID file)")
			return
		}

		pidStr := string(pidBytes)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			common.ErrorLogger.Printf("Error parsing PID: %v", err)
			fmt.Println("Gero status: Unknown (error parsing PID)")
			return
		}

		// Check if process is running
		process, err := os.FindProcess(pid)
		if err != nil {
			fmt.Println("Gero is not running")
			return
		}

		// Send signal 0 to process to check if it exists
		err = process.Signal(syscall.Signal(0))
		if err != nil {
			fmt.Println("Gero is not running")
			// Clean up stale PID file
			os.Remove(pidFile)
			return
		}

		fmt.Printf("Gero is running (PID: %d)\n", pid)

		// Check log files
		logDir := filepath.Join(os.Getenv("HOME"), ".gero", "logs")
		stdoutLatestPath := filepath.Join(logDir, "gero_latest.log")
		stderrLatestPath := filepath.Join(logDir, "gero_latest.err")

		fmt.Println("Log files:")
		fmt.Printf("  Standard log: %s\n", stdoutLatestPath)
		fmt.Printf("  Error log: %s\n", stderrLatestPath)
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
