// Package event builds the message the CLI publishes.
package event

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Backup is the message published on <code>.<AGENT_KIND>.events.
type Backup struct {
	BackupSessionName       string    `json:"backupSessionName"`
	BackupSessionNamespace  string    `json:"backupSessionNamespace"`
	BackupConfigurationName string    `json:"backupConfigurationName"`
	Message                 string    `json:"message"`
	Phase                   string    `json:"phase"`
	Kind                    string    `json:"kind"`
	UUID                    string    `json:"uuid"`
	Time                    time.Time `json:"time"`
}

// Input is what the user passes on the command line.
type Input struct {
	BackupSessionName       string
	BackupSessionNamespace  string
	BackupConfigurationName string
	Message                 string
	Phase                   string
}

// Validate reports every field that is empty or only whitespace.
func (in Input) Validate() error {
	var missing []string
	for _, f := range []struct{ name, v string }{
		{"backupSessionName", in.BackupSessionName},
		{"backupSessionNamespace", in.BackupSessionNamespace},
		{"backupConfigurationName", in.BackupConfigurationName},
		{"message", in.Message},
		{"phase", in.Phase},
	} {
		if strings.TrimSpace(f.v) == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("empty value for: %s", strings.Join(missing, ", "))
	}
	return nil
}

// NewBackup builds the message from the user's input, the agent's kind and uuid, and now.
func NewBackup(in Input, kind, uuid string, now time.Time) (Backup, error) {
	if err := in.Validate(); err != nil {
		return Backup{}, err
	}
	if kind == "" || uuid == "" {
		return Backup{}, errors.New("agent kind and uuid must not be empty")
	}
	return Backup{
		BackupSessionName:       in.BackupSessionName,
		BackupSessionNamespace:  in.BackupSessionNamespace,
		BackupConfigurationName: in.BackupConfigurationName,
		Message:                 in.Message,
		Phase:                   in.Phase,
		Kind:                    kind,
		UUID:                    uuid,
		Time:                    now.UTC(),
	}, nil
}

// Subject is where an agent of this kind sends events: <code>.<kind>.events. The server
// grants a backup agent <code>.backup.events, and refuses a subject without the code.
func Subject(code, kind string) string { return code + "." + kind + ".events" }
