package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/Superm4n97/helm-artifacts/nats-agent/pkg/agent"
)

func newPublishCmd() *cobra.Command {
	var suffix, message string
	c := &cobra.Command{
		Use:   "publish",
		Short: "Publish a message on <code>.<subject-suffix>",
		Long: `Connects with the agent Secret, learns the agent's code from $SYS.REQ.USER.INFO,
and publishes the message on <code>.<subject-suffix>.

The default message is 'my-kind: $AGENT_KIND, my-uuid: $AGENT_UUID'.`,
		Example: `  nats-agent publish
  nats-agent publish --subject-suffix agent.status --message 'hello'`,
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
			log.Printf("identity=%s code=%s", info.Identity, info.Code)

			if !cmd.Flags().Changed("message") {
				message = fmt.Sprintf("my-kind: %s, my-uuid: %s", cfg.Kind, cfg.UUID)
			}
			subject := info.Code + "." + suffix
			if err := c.Publish(subject, []byte(message)); err != nil {
				return err
			}
			log.Printf("published to %s: %q", subject, message)
			return nil
		},
	}
	c.Flags().StringVar(&suffix, "subject-suffix", "agent.status", "subject after the agent's code; must be in the agent's publish grant")
	c.Flags().StringVar(&message, "message", "", "message body (default 'my-kind: $AGENT_KIND, my-uuid: $AGENT_UUID')")
	return c
}

func newWhoamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Connect and print the agent's identity, code and publish grant",
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
			fmt.Printf("identity: %s\ncode:     %s\npublish:  %v\n", info.Identity, info.Code, info.PublishAllow)
			return nil
		},
	}
}

func loadConfig(cmd *cobra.Command) (agent.Config, error) {
	dir, _ := cmd.Flags().GetString("secret-dir")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	return agent.LoadConfig(dir, timeout)
}
