package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "1.0.0"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Gero",
	Long:  `Display the version number, build time, and git commit of Gero.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Gero version %s\n", Version)
		fmt.Printf("Build time: %s\n", BuildTime)
		fmt.Printf("Git commit: %s\n", GitCommit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
