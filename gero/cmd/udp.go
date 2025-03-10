package cmd

import (
	"fmt"
	"strconv"

	"github.com/c0rex86/gero/internal/client"
	"github.com/c0rex86/gero/internal/common"
	"github.com/spf13/cobra"
)

var (
	udpLocalPort  int
	udpRemotePort int
)

var udpCmd = &cobra.Command{
	Use:   "udp",
	Short: "UDP tunnel management",
	Long:  `Commands for creating and managing UDP tunnels.`,
}

var udpCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create UDP tunnel",
	Long:  `Create a UDP tunnel from local port to remote port.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		serverAddr := common.GetDefaultServer()
		serverPort := common.GetDefaultPort()
		key := common.GetSecretKey()

		client.CreateUDPTunnel(serverAddr, serverPort, key, uint16(udpLocalPort), uint16(udpRemotePort))
	},
}

var udpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active UDP tunnels",
	Long:  `List all active UDP tunnels.`,
	Run: func(cmd *cobra.Command, args []string) {
		tunnels := client.ListUDPTunnels()
		if len(tunnels) == 0 {
			fmt.Println("No active UDP tunnels")
			return
		}

		fmt.Println("Active UDP tunnels:")
		fmt.Println("LOCAL PORT\tREMOTE PORT")
		for _, tunnel := range tunnels {
			fmt.Printf("%d\t\t%d\n", tunnel.LocalPort, tunnel.RemotePort)
		}
	},
}

var udpCloseCmd = &cobra.Command{
	Use:   "close [local_port]",
	Short: "Close UDP tunnel",
	Long:  `Close a UDP tunnel by its local port.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		port, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Invalid port number: %v\n", err)
			return
		}

		if client.CloseUDPTunnel(uint16(port)) {
			fmt.Printf("UDP tunnel on local port %d closed\n", port)
		} else {
			fmt.Printf("No UDP tunnel found on local port %d\n", port)
		}
	},
}

func init() {
	rootCmd.AddCommand(udpCmd)

	udpCmd.AddCommand(udpCreateCmd)
	udpCmd.AddCommand(udpListCmd)
	udpCmd.AddCommand(udpCloseCmd)

	udpCreateCmd.Flags().IntVarP(&udpLocalPort, "local", "l", 0, "Local port (0 for auto-assign)")
	udpCreateCmd.Flags().IntVarP(&udpRemotePort, "remote", "r", 0, "Remote port (0 for auto-assign)")
}
