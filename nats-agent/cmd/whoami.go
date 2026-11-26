package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Superm4n97/artifacts/nats-agent/pkg/agent"
)

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Connect and print the agent's identity, code and publish grant",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			c, err := agent.Connect(cfg)
			if err != nil {
				return err
			}
			defer c.Close()
			info, err := c.UserInfo()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "identity: %s\n", info.Identity)
			fmt.Fprintf(out, "code:     %s (computed %s)\n", info.Code, agent.Code(agent.AgentIdentity(cfg.UUID)))
			fmt.Fprintf(out, "publish:  %v\n", info.PublishAllow)
			return nil
		},
	}
}
