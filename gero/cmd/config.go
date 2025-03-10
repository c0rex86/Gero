package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/c0rex86/gero/internal/common"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Gero configuration",
	Long:  `Manage Gero configuration settings like secret key, default server, etc.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display all current configuration settings.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		fmt.Println("Current Configuration:")
		fmt.Printf("Secret Key: %s\n", common.GetSecretKey())
		fmt.Printf("Default Server: %s\n", common.GetDefaultServer())
		fmt.Printf("Default Port: %d\n", common.GetDefaultPort())
	},
}

var configSetKeyCmd = &cobra.Command{
	Use:   "set-key [key]",
	Short: "Set the secret key",
	Long:  `Set the secret key used for authentication between client and server.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		key := args[0]
		common.SetSecretKey(key)
		fmt.Printf("Secret key updated to: %s\n", key)
	},
}

var configSetServerCmd = &cobra.Command{
	Use:   "set-server [server]",
	Short: "Set the default server",
	Long:  `Set the default server address used by the client.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		server := args[0]
		common.SetDefaultServer(server)
		fmt.Printf("Default server updated to: %s\n", server)
	},
}

var configSetPortCmd = &cobra.Command{
	Use:   "set-port [port]",
	Short: "Set the default port",
	Long:  `Set the default port used by both client and server.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := common.LoadConfig(); err != nil {
			common.ErrorLogger.Printf("Error loading config: %v", err)
			return
		}

		port, err := strconv.Atoi(args[0])
		if err != nil {
			common.ErrorLogger.Printf("Invalid port number: %v", err)
			return
		}

		common.SetDefaultPort(port)
		fmt.Printf("Default port updated to: %d\n", port)
	},
}

var configSetTOTPSecretCmd = &cobra.Command{
	Use:   "set-totp-secret",
	Short: "Generate and set TOTP secret",
	Long:  `Generate and set the TOTP secret for two-factor authentication.`,
	Run: func(cmd *cobra.Command, args []string) {
		qrURL, err := common.SetupTOTP()
		if err != nil {
			common.ErrorLogger.Printf("Error setting up TOTP: %v", err)
			return
		}

		fmt.Println("TOTP secret generated successfully!")
		fmt.Println("To set up your authenticator app, scan this QR code or enter the secret manually.")

		homeDir, err := os.UserHomeDir()
		if err != nil {
			common.ErrorLogger.Printf("Error getting home directory: %v", err)
			return
		}

		filePath := filepath.Join(homeDir, "gero_totp_qr.txt")
		err = common.GenerateTOTPQR(qrURL, filePath)
		if err != nil {
			common.ErrorLogger.Printf("Error generating QR code: %v", err)
			return
		}

		fmt.Println("\nFor TOTP URL: (copy this to a QR code generator if needed)")
		fmt.Println(qrURL)
		fmt.Printf("\nQR code URL saved to: %s\n", filePath)
		fmt.Println("\nAfter setting up your authenticator app, enable TOTP on the server with:")
		fmt.Println("  gero server --require-totp")
	},
}

// Новые команды для управления IP-фильтрацией
var configIPFilterCmd = &cobra.Command{
	Use:   "ipfilter",
	Short: "Manage IP filtering",
	Long:  `Manage IP filtering settings for server access control.`,
}

var configAddIPCmd = &cobra.Command{
	Use:   "add-ip [ip]",
	Short: "Add IP to allowed list",
	Long:  `Add an IP address or CIDR range to the allowed access list.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ip := args[0]

		// Загружаем текущий список разрешенных IP
		ips, err := common.LoadAllowedIPs()
		if err != nil {
			common.ErrorLogger.Printf("Error loading allowed IPs: %v", err)
			return
		}

		// Добавляем новый IP и сохраняем обновленный список
		ips = append(ips, ip)
		if err := common.SaveAllowedIPs(ips); err != nil {
			common.ErrorLogger.Printf("Error saving allowed IPs: %v", err)
			return
		}

		fmt.Printf("Added %s to allowed IP list\n", ip)
		fmt.Println("IP filtering can be enabled with: gero server --ip-filter")
	},
}

var configListIPCmd = &cobra.Command{
	Use:   "list-ip",
	Short: "List allowed IPs",
	Long:  `List all IP addresses or CIDR ranges in the allowed access list.`,
	Run: func(cmd *cobra.Command, args []string) {
		ips, err := common.LoadAllowedIPs()
		if err != nil {
			common.ErrorLogger.Printf("Error loading allowed IPs: %v", err)
			return
		}

		if len(ips) == 0 {
			fmt.Println("No IPs in allowed list.")
			return
		}

		fmt.Println("Allowed IP addresses:")
		for i, ip := range ips {
			fmt.Printf("%d. %s\n", i+1, ip)
		}
	},
}

var configRemoveIPCmd = &cobra.Command{
	Use:   "remove-ip [ip]",
	Short: "Remove IP from allowed list",
	Long:  `Remove an IP address or CIDR range from the allowed access list.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ipToRemove := args[0]

		// Загружаем текущий список разрешенных IP
		ips, err := common.LoadAllowedIPs()
		if err != nil {
			common.ErrorLogger.Printf("Error loading allowed IPs: %v", err)
			return
		}

		// Создаем новый список без указанного IP
		newIPs := []string{}
		found := false
		for _, ip := range ips {
			if ip != ipToRemove {
				newIPs = append(newIPs, ip)
			} else {
				found = true
			}
		}

		if !found {
			fmt.Printf("IP %s not found in allowed list\n", ipToRemove)
			return
		}

		// Сохраняем обновленный список
		if err := common.SaveAllowedIPs(newIPs); err != nil {
			common.ErrorLogger.Printf("Error saving allowed IPs: %v", err)
			return
		}

		fmt.Printf("Removed %s from allowed IP list\n", ipToRemove)
	},
}

// Команды для управления маршрутами
var configRoutesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Manage route configurations",
	Long:  `Manage route configurations for port forwarding.`,
}

var configListRoutesCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured routes",
	Long:  `List all configured routes for port forwarding.`,
	Run: func(cmd *cobra.Command, args []string) {
		routes, err := common.GetRoutes()
		if err != nil {
			common.ErrorLogger.Printf("Error loading routes: %v", err)
			return
		}

		if len(routes) == 0 {
			fmt.Println("No routes configured.")
			return
		}

		fmt.Println("Configured routes:")
		fmt.Println("----------------------------------")
		for i, route := range routes {
			fmt.Printf("%d. %s\n", i+1, route.Name)
			fmt.Printf("   Local port: %d\n", route.LocalPort)
			fmt.Printf("   Remote host: %s\n", route.RemoteHost)
			fmt.Printf("   Remote port: %d\n", route.RemotePort)
			fmt.Printf("   Protocol: %s\n", route.Protocol)
			fmt.Println("----------------------------------")
		}
	},
}

var configAddRouteCmd = &cobra.Command{
	Use:   "add [name] [local_port] [remote_host] [remote_port] [protocol]",
	Short: "Add a new route",
	Long:  `Add a new route configuration for port forwarding.`,
	Args:  cobra.ExactArgs(5),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		localPort, err := strconv.Atoi(args[1])
		if err != nil {
			common.ErrorLogger.Printf("Invalid local port: %v", err)
			return
		}

		remoteHost := args[2]
		remotePort, err := strconv.Atoi(args[3])
		if err != nil {
			common.ErrorLogger.Printf("Invalid remote port: %v", err)
			return
		}

		protocol := args[4]
		if protocol != "tcp" && protocol != "udp" {
			common.ErrorLogger.Printf("Invalid protocol. Must be 'tcp' or 'udp'")
			return
		}

		// Create route config
		route := common.RouteConfig{
			Name:       name,
			LocalPort:  localPort,
			RemoteHost: remoteHost,
			RemotePort: remotePort,
			Protocol:   protocol,
		}

		// Add the route
		if err := common.AddRoute(route); err != nil {
			common.ErrorLogger.Printf("Error adding route: %v", err)
			return
		}

		fmt.Printf("Added route '%s'\n", name)
		fmt.Printf("To use it: gero connect %s\n", name)
	},
}

var configRemoveRouteCmd = &cobra.Command{
	Use:   "remove [name]",
	Short: "Remove a route",
	Long:  `Remove a route configuration by name.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]

		// Remove the route
		if err := common.RemoveRoute(name); err != nil {
			common.ErrorLogger.Printf("Error removing route: %v", err)
			return
		}

		fmt.Printf("Removed route '%s'\n", name)
	},
}

func init() {
	rootCmd.AddCommand(configCmd)

	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetKeyCmd)
	configCmd.AddCommand(configSetServerCmd)
	configCmd.AddCommand(configSetPortCmd)
	configCmd.AddCommand(configSetTOTPSecretCmd)

	configCmd.AddCommand(configIPFilterCmd)
	configIPFilterCmd.AddCommand(configAddIPCmd)
	configIPFilterCmd.AddCommand(configListIPCmd)
	configIPFilterCmd.AddCommand(configRemoveIPCmd)

	configCmd.AddCommand(configRoutesCmd)
	configRoutesCmd.AddCommand(configListRoutesCmd)
	configRoutesCmd.AddCommand(configAddRouteCmd)
	configRoutesCmd.AddCommand(configRemoveRouteCmd)
}
