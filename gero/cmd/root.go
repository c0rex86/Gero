package cmd

import (
	"fmt"
	"os"

	"github.com/c0rex86/gero/internal/common"
	"github.com/spf13/cobra"
)

var (
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "gero",
	Short: "Gero - Network access tool",
	Long:  `Gero is a tool for accessing local networks through a server-client tunnel.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		common.InitLogging(verbose)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}
