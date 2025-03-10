package cmd

import (
	"fmt"
	"strconv"

	"github.com/c0rex86/gero/internal/client"
	"github.com/c0rex86/gero/internal/common"
	"github.com/spf13/cobra"
)

var (
	tcpLocalPort  int
	tcpRemotePort int
	tcpRemoteHost string
)

var tcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "TCP route management",
	Long:  `Commands for creating and managing TCP routes.`,
}

var tcpCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create TCP route",
	Long:  `Create a TCP route from local port to remote host:port.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		actualPort, err := client.CreateTCPRoute(uint16(tcpLocalPort), tcpRemoteHost, uint16(tcpRemotePort))
		if err != nil {
			fmt.Printf("Error creating TCP route: %v\n", err)
			return
		}

		fmt.Printf("TCP route created: 127.0.0.1:%d -> %s:%d\n", actualPort, tcpRemoteHost, tcpRemotePort)
		if tcpLocalPort == 0 {
			fmt.Printf("Automatically assigned local port: %d\n", actualPort)
		}
	},
}

var tcpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active TCP routes",
	Long:  `List all active TCP routes.`,
	Run: func(cmd *cobra.Command, args []string) {
		routes := client.ListTCPRoutes()
		if len(routes) == 0 {
			fmt.Println("No active TCP routes")
			return
		}

		fmt.Println("Active TCP routes:")
		fmt.Println("LOCAL PORT\tREMOTE HOST\tREMOTE PORT\tSTATUS\tCONNECTIONS")
		for _, route := range routes {
			fmt.Printf("%d\t\t%s\t\t%d\t\t%s\t%d\n",
				route.LocalPort, route.RemoteHost, route.RemotePort, route.Status, route.Connections)
		}
	},
}

var tcpCloseCmd = &cobra.Command{
	Use:   "close [local_port]",
	Short: "Close TCP route",
	Long:  `Close a TCP route by its local port.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		port, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Invalid port number: %v\n", err)
			return
		}

		if client.CloseTCPRoute(uint16(port)) {
			fmt.Printf("TCP route on local port %d closed\n", port)
		} else {
			fmt.Printf("No TCP route found on local port %d\n", port)
		}
	},
}

var tcpInfoCmd = &cobra.Command{
	Use:   "info [local_port]",
	Short: "Show TCP route info",
	Long:  `Show detailed information about a TCP route.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		port, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Invalid port number: %v\n", err)
			return
		}

		route, exists := client.GetTCPRouteInfo(uint16(port))
		if !exists {
			fmt.Printf("No TCP route found on local port %d\n", port)
			return
		}

		fmt.Printf("TCP Route Information:\n")
		fmt.Printf("  Local Port:    %d\n", route.LocalPort)
		fmt.Printf("  Remote Host:   %s\n", route.RemoteHost)
		fmt.Printf("  Remote Port:   %d\n", route.RemotePort)
		fmt.Printf("  Status:        %s\n", route.Status)
		fmt.Printf("  Connections:   %d\n", route.Connections)
	},
}

func init() {
	rootCmd.AddCommand(tcpCmd)

	tcpCmd.AddCommand(tcpCreateCmd)
	tcpCmd.AddCommand(tcpListCmd)
	tcpCmd.AddCommand(tcpCloseCmd)
	tcpCmd.AddCommand(tcpInfoCmd)

	tcpCreateCmd.Flags().IntVarP(&tcpLocalPort, "local", "l", 0, "Local port (0 for auto-assign)")
	tcpCreateCmd.Flags().IntVarP(&tcpRemotePort, "port", "p", 80, "Remote port")
	tcpCreateCmd.Flags().StringVarP(&tcpRemoteHost, "host", "H", "localhost", "Remote host")
}
