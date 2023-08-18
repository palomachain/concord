package main

import (
	"github.com/palomachain/pigeon/app"
	"github.com/palomachain/pigeon/internal/liblog"
	"github.com/spf13/cobra"
)

// flags
var (
	flagConfigPath     string
	configRequiredCmds []*cobra.Command
)

var rootCmd = &cobra.Command{
	Use:          "pigeon",
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		found := false
		for _, curr := range configRequiredCmds {
			if curr == cmd {
				found = true
				break
			}
		}
		if found {
			app.SetConfigPath(flagConfigPath)
		}

		ctx := liblog.EnrichContext(cmd.Context())
		cmd.SetContext(ctx)
	},
}

func configRequired(cmd *cobra.Command) {
	for _, curr := range configRequiredCmds {
		if curr == cmd {
			return
		}
	}
	configRequiredCmds = append(configRequiredCmds, cmd)
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagConfigPath, "config", "c", "~/.pigeon/config.yaml", "path to the config file")
}
