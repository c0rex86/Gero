package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/c0rex86/gero/internal/common"
	"github.com/c0rex86/gero/internal/server"
	"github.com/spf13/cobra"
)

var (
	serverPort        int
	serverDaemon      bool
	serverIPFilter    bool
	serverRequireTOTP bool
	serverSSL         bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Gero server",
	Long:  `Start the Gero server to listen for incoming connections.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Инициализируем конфигурацию
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Fatalf("Failed to load config: %v", err)
		}

		// Загружаем дополнительные конфигурации если нужны
		if serverIPFilter {
			_, err := common.LoadAllowedIPs()
			if err != nil {
				common.ErrorLogger.Printf("Failed to load allowed IPs: %v", err)
				common.ErrorLogger.Printf("IP filtering will be disabled. Please configure allowed IPs with: gero config ipfilter add-ip")
				serverIPFilter = false
			}
		}

		if serverRequireTOTP {
			_, err := common.LoadTOTPSecret()
			if err != nil {
				common.ErrorLogger.Printf("Failed to load TOTP secret: %v", err)
				common.ErrorLogger.Printf("TOTP authentication will be disabled. Please set up TOTP with: gero config set-totp-secret")
				serverRequireTOTP = false
			}
		}

		// Если запуск как демон, пересоздаем процесс
		if serverDaemon {
			fmt.Println("Starting Gero server in background...")
			cmd := exec.Command(os.Args[0], "server",
				fmt.Sprintf("--port=%d", serverPort),
				"--no-daemon")

			// Убираем флаги для демона
			cmd.Env = os.Environ()
			cmd.Stdout = nil
			cmd.Stderr = nil
			cmd.Stdin = nil

			if err := cmd.Start(); err != nil {
				common.ErrorLogger.Fatalf("Failed to start daemon: %v", err)
			}

			fmt.Printf("Gero server is running in background (PID: %d)\n", cmd.Process.Pid)
			return
		}

		// Запускаем сервер
		fmt.Printf("Starting Gero server on port %d...\n", serverPort)
		if serverIPFilter {
			fmt.Println("IP filtering is enabled.")
		}
		if serverRequireTOTP {
			fmt.Println("TOTP authentication is enabled.")
		}

		if err := server.StartServer(serverPort, serverIPFilter, serverRequireTOTP, false); err != nil {
			common.ErrorLogger.Fatalf("Server error: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)

	// Флаги команды
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "Port to listen on")
	serverCmd.Flags().BoolVarP(&serverDaemon, "daemon", "d", false, "Run server as a daemon")
	serverCmd.Flags().BoolVar(&serverDaemon, "no-daemon", false, "Run server in foreground (internal use)")
	serverCmd.Flags().MarkHidden("no-daemon")

	// Новые флаги для расширенных функций
	serverCmd.Flags().BoolVar(&serverIPFilter, "ip-filter", false, "Enable IP filtering")
	serverCmd.Flags().BoolVar(&serverRequireTOTP, "require-totp", false, "Require TOTP authentication")
	serverCmd.Flags().BoolVar(&serverSSL, "ssl", false, "Enable SSL/TLS encryption")
}
