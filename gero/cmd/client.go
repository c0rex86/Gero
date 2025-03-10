package cmd

import (
	"github.com/c0rex86/gero/internal/client"
	"github.com/c0rex86/gero/internal/common"
	"github.com/spf13/cobra"
)

var (
	clientServerAddr string
	clientServerPort int
	clientDaemon     bool
	clientKey        string
)

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Start Gero client",
	Long:  `Start Gero client which connects to a server to access a local network.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Load config to get defaults
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		// Use defaults from config if not specified
		if cmd.Flags().Changed("server") == false {
			clientServerAddr = common.GetDefaultServer()
		}

		if cmd.Flags().Changed("port") == false {
			clientServerPort = common.GetDefaultPort()
		}

		if cmd.Flags().Changed("key") == false {
			clientKey = common.GetSecretKey()
		}

		if clientDaemon {
			client.StartDaemon(clientServerAddr, clientServerPort, clientKey)
		} else {
			client.Start(clientServerAddr, clientServerPort, clientKey)
		}
	},
}

func init() {
	rootCmd.AddCommand(clientCmd)

	clientCmd.Flags().StringVarP(&clientServerAddr, "server", "s", "localhost", "Server address to connect to")
	clientCmd.Flags().IntVarP(&clientServerPort, "port", "p", 8080, "Server port to connect to")
	clientCmd.Flags().BoolVarP(&clientDaemon, "daemon", "d", false, "Run as daemon")
	clientCmd.Flags().StringVarP(&clientKey, "key", "k", "", "Authentication key")
}
