package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	SecretKey     string `json:"secret_key"`
	DefaultServer string `json:"default_server"`
	DefaultPort   int    `json:"default_port"`
}

var (
	DefaultConfig = Config{
		SecretKey:     "gero-secret-key",
		DefaultServer: "localhost",
		DefaultPort:   8080,
	}

	CurrentConfig = DefaultConfig
)

func ConfigDir() string {
	configDir := filepath.Join(os.Getenv("HOME"), ".gero")
	return configDir
}

func ConfigFile() string {
	return filepath.Join(ConfigDir(), "config.json")
}

func LoadConfig() error {
	configFile := ConfigFile()

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return SaveConfig()
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	err = json.Unmarshal(data, &CurrentConfig)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

func SaveConfig() error {
	configDir := ConfigDir()

	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(CurrentConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(ConfigFile(), data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func SetSecretKey(key string) {
	CurrentConfig.SecretKey = key
	SaveConfig()
}

func GetSecretKey() string {
	return CurrentConfig.SecretKey
}

func SetDefaultServer(server string) {
	CurrentConfig.DefaultServer = server
	SaveConfig()
}

func GetDefaultServer() string {
	return CurrentConfig.DefaultServer
}

func SetDefaultPort(port int) {
	CurrentConfig.DefaultPort = port
	SaveConfig()
}

func GetDefaultPort() int {
	return CurrentConfig.DefaultPort
}
