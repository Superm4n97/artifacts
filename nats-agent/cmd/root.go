package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

// Version is set at build time with -ldflags "-X .../cmd.Version=...".
var Version = "dev"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "nats-agent",
		Short:         "Talk to the platform NATS servers with a datacenter agent Secret",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().String("secret-dir", "/etc/nats-agent",
		"directory where the agent Secret is mounted (NATS_URLS, NATS_TENANT, NATS_TOKEN, NATS_SENTINEL, AGENT_KIND, AGENT_UUID, ca.cert|ca.crt)")
	root.PersistentFlags().Duration("timeout", 10*time.Second, "connect and request timeout")

	root.AddCommand(newPublishCmd(), newWhoamiCmd())
	return root
}
