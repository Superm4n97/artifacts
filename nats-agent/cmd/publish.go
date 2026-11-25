package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"
	"github.com/spf13/cobra"

	"github.com/Superm4n97/helm-artifacts/nats-agent/pkg/agent"
	"github.com/Superm4n97/helm-artifacts/nats-agent/pkg/event"
)

// now is replaced in tests.
var now = time.Now

func newPublishCmd() *cobra.Command {
	var in event.Input
	c := &cobra.Command{
		Use:   "publish",
		Short: "Publish a backup event on <code>.<AGENT_KIND>.events",
		Long: `Connects with the agent Secret and sends this JSON as a request on
<code>.<AGENT_KIND>.events, then waits for the platform's answer:

  {
    "backupSessionName":       --backupSessionName,
    "backupSessionNamespace":  --backupSessionNamespace,
    "backupConfigurationName": --backupConfigurationName,
    "message":                 --message,
    "phase":                   --phase,
    "kind":                    AGENT_KIND from the Secret,
    "uuid":                    AGENT_UUID from the Secret,
    "time":                    now, RFC 3339 UTC
  }

<code> is the agent's code, taken from the server's $SYS.REQ.USER.INFO answer.`,
		Example: `  nats-agent publish --secret-dir /etc/nats-agent \
    --backupSessionName bs-1 --backupSessionNamespace demo \
    --backupConfigurationName bc-1 --phase Succeeded --message 'backup done'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := in.Validate(); err != nil {
				return err
			}
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			ev, err := event.NewBackup(in, cfg.Kind, cfg.UUID, now())
			if err != nil {
				return err
			}
			body, err := json.Marshal(ev)
			if err != nil {
				return err
			}

			c, err := agent.Connect(cfg)
			if err != nil {
				return err
			}
			defer c.Close()

			code, err := resolveCode(c, cfg)
			if err != nil {
				return err
			}
			subject := event.Subject(code, cfg.Kind)

			h := nats.Header{}
			h.Set("Nats-Msg-Id", nuid.Next())
			h.Set("schema-version", "v1")
			if _, err := c.Request(subject, body, h); err != nil {
				return err
			}
			log.Printf("published to %s: %s", subject, body)
			fmt.Fprintln(cmd.OutOrStdout(), string(body))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&in.BackupSessionName, "backupSessionName", "", "name of the BackupSession (required)")
	f.StringVar(&in.BackupSessionNamespace, "backupSessionNamespace", "", "namespace of the BackupSession (required)")
	f.StringVar(&in.BackupConfigurationName, "backupConfigurationName", "", "name of the BackupConfiguration (required)")
	f.StringVar(&in.Message, "message", "", "message (required)")
	f.StringVar(&in.Phase, "phase", "", "phase of the BackupSession (required)")
	for _, name := range []string{"backupSessionName", "backupSessionNamespace", "backupConfigurationName", "message", "phase"} {
		_ = c.MarkFlagRequired(name)
	}
	return c
}

// resolveCode takes the code from the server's grant, and falls back to computing it from
// AGENT_UUID when the server grants nothing (the computation is stable by contract).
func resolveCode(c *agent.Client, cfg agent.Config) (string, error) {
	computed := agent.Code(agent.AgentIdentity(cfg.UUID))
	info, err := c.UserInfo()
	if err != nil {
		return "", err
	}
	switch {
	case info.Code == "":
		log.Printf("server granted no code; using code %s computed from AGENT_UUID", computed)
		return computed, nil
	case info.Code != computed:
		log.Printf("warning: server code %s differs from computed %s; using the server's", info.Code, computed)
	}
	log.Printf("identity=%s code=%s", info.Identity, info.Code)
	return info.Code, nil
}

func loadConfig(cmd *cobra.Command) (agent.Config, error) {
	dir, _ := cmd.Flags().GetString("secret-dir")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	return agent.LoadConfig(dir, timeout)
}
