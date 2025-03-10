package common

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	allowedIPs      []string
	ipFilterMutex   sync.Mutex
	ipFilterEnabled bool
)

// LoadAllowedIPs loads allowed IP addresses from configuration file
// Returns a slice of allowed IP addresses/ranges and any error encountered
func LoadAllowedIPs() ([]string, error) {
	ipFilterMutex.Lock()
	defer ipFilterMutex.Unlock()

	// Get config directory
	configDir := ConfigDir()

	// Path to allowed IPs file
	ipFilePath := filepath.Join(configDir, "allowed_ips.txt")

	// Check if file exists
	if _, err := os.Stat(ipFilePath); os.IsNotExist(err) {
		// File doesn't exist, create an empty one
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, err
		}
		file, err := os.Create(ipFilePath)
		if err != nil {
			return nil, err
		}
		file.Close()
		allowedIPs = []string{}
		return allowedIPs, nil
	}

	// Open file
	file, err := os.Open(ipFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read IP addresses line by line
	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Validate IP and add CIDR if not present
		ip := line
		if !strings.Contains(ip, "/") {
			if strings.Contains(ip, ":") {
				// IPv6 address, add /128 if no CIDR
				ip = ip + "/128"
			} else {
				// IPv4 address, add /32 if no CIDR
				ip = ip + "/32"
			}
		}

		// Parse to validate the IP/CIDR
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			// If it's not valid CIDR, try as regular IP
			ipObj := net.ParseIP(line)
			if ipObj == nil {
				InfoLogger.Printf("Invalid IP address or CIDR range, skipping: %s", line)
				continue
			}

			// Valid IP, convert to CIDR
			if strings.Contains(line, ":") {
				ip = line + "/128"
			} else {
				ip = line + "/32"
			}
		}

		ips = append(ips, ip)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	allowedIPs = ips
	return ips, nil
}

// SaveAllowedIPs saves the provided list of IPs to the configuration file
func SaveAllowedIPs(ips []string) error {
	ipFilterMutex.Lock()
	defer ipFilterMutex.Unlock()

	// Get config directory
	configDir := ConfigDir()

	// Ensure directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	// Path to allowed IPs file
	ipFilePath := filepath.Join(configDir, "allowed_ips.txt")

	// Open file for writing
	file, err := os.Create(ipFilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header comment
	file.WriteString("# Allowed IP addresses for Gero server\n")
	file.WriteString("# Each line should contain an IP address or CIDR range\n\n")

	// Write each IP on a separate line
	for _, ip := range ips {
		file.WriteString(ip + "\n")
	}

	// Update the global variable
	allowedIPs = ips

	return nil
}

// EnableIPFilter enables or disables the IP filtering feature
func EnableIPFilter(enabled bool) {
	ipFilterMutex.Lock()
	defer ipFilterMutex.Unlock()
	ipFilterEnabled = enabled
}

// IsIPFilterEnabled returns whether IP filtering is currently enabled
func IsIPFilterEnabled() bool {
	ipFilterMutex.Lock()
	defer ipFilterMutex.Unlock()
	return ipFilterEnabled
}

// IsIPAllowed checks if a given IP address is allowed to access the server
func IsIPAllowed(ipStr string) bool {
	ipFilterMutex.Lock()
	defer ipFilterMutex.Unlock()

	if !ipFilterEnabled || len(allowedIPs) == 0 {
		return true // Allow all if filter is disabled or no IPs defined
	}

	// Parse the IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		InfoLogger.Printf("Invalid IP address format: %s", ipStr)
		return false
	}

	// Check against allowed IPs/ranges
	for _, allowedIP := range allowedIPs {
		// Check if it's a CIDR range
		if strings.Contains(allowedIP, "/") {
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err != nil {
				continue // Skip invalid CIDR
			}

			if ipNet.Contains(ip) {
				return true
			}
		} else {
			// Direct IP comparison
			if allowedIP == ipStr {
				return true
			}
		}
	}

	// IP not allowed
	InfoLogger.Printf("Access denied for IP: %s", ipStr)
	return false
}
