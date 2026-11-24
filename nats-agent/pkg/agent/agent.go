// Package agent connects to the platform NATS servers the way a datacenter agent does:
// sentinel JWT signed by a per-process inbox key, tenant as user, inbox public key as
// password, and the bearer token as auth_token (re-read from disk on every connect).
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

type Config struct {
	Dir      string
	URLs     string
	Tenant   string
	Sentinel string
	Kind     string
	UUID     string
	CAFile   string // empty: system roots
	Timeout  time.Duration
}

func readKey(dir, key string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, key))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", key, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// LoadConfig reads the mounted agent Secret. NATS_TOKEN is not read here: it is read at
// each connect so a rotated token is picked up.
func LoadConfig(dir string, timeout time.Duration) (Config, error) {
	cfg := Config{Dir: dir, Timeout: timeout}
	for key, dst := range map[string]*string{
		"NATS_URLS":     &cfg.URLs,
		"NATS_TENANT":   &cfg.Tenant,
		"NATS_SENTINEL": &cfg.Sentinel,
		"AGENT_KIND":    &cfg.Kind,
		"AGENT_UUID":    &cfg.UUID,
	} {
		v, err := readKey(dir, key)
		if err != nil {
			return cfg, err
		}
		*dst = v
	}
	if _, err := readKey(dir, "NATS_TOKEN"); err != nil {
		return cfg, err
	}
	for _, ca := range []string{"ca.cert", "ca.crt"} {
		if _, err := os.Stat(filepath.Join(dir, ca)); err == nil {
			cfg.CAFile = filepath.Join(dir, ca)
			break
		}
	}
	return cfg, nil
}

type Client struct {
	nc      *nats.Conn
	timeout time.Duration
}

func Connect(cfg Config) (*Client, error) {
	inbox, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	pass, err := inbox.PublicKey()
	if err != nil {
		return nil, err
	}

	opts := []nats.Option{
		nats.Name("nats-agent-" + cfg.Kind),
		nats.Secure(),
		nats.TokenHandler(func() string {
			t, err := readKey(cfg.Dir, "NATS_TOKEN")
			if err != nil {
				log.Printf("token: %v", err)
			}
			return t
		}),
		nats.UserJWT(func() (string, error) { return cfg.Sentinel, nil }, inbox.Sign),
		nats.UserInfo(cfg.Tenant, pass),
		nats.CustomInboxPrefix("_INBOX." + pass),
		nats.Timeout(cfg.Timeout),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Printf("nats async error: %v", err)
		}),
	}
	if cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.CAFile))
	}

	nc, err := nats.Connect(cfg.URLs, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	log.Printf("connected to %s", nc.ConnectedUrlRedacted())
	return &Client{nc: nc, timeout: cfg.Timeout}, nil
}

func (c *Client) Close() { c.nc.Close() }

type UserInfo struct {
	Identity     string
	Code         string
	PublishAllow []string
}

// UserInfo asks the server who this connection is. The code is the first token of the
// publish grants that are not $SYS subjects.
func (c *Client) UserInfo() (UserInfo, error) {
	msg, err := c.nc.Request("$SYS.REQ.USER.INFO", nil, c.timeout)
	if err != nil {
		return UserInfo{}, fmt.Errorf("user info: %w", err)
	}
	var resp struct {
		Data struct {
			User        string `json:"user"`
			Permissions struct {
				Publish struct {
					Allow []string `json:"allow"`
				} `json:"publish"`
			} `json:"permissions"`
		} `json:"data"`
		Error *struct {
			Description string `json:"description"`
		} `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return UserInfo{}, fmt.Errorf("parse user info: %w", err)
	}
	if resp.Error != nil {
		return UserInfo{}, fmt.Errorf("user info: %s", resp.Error.Description)
	}
	info := UserInfo{Identity: resp.Data.User, PublishAllow: resp.Data.Permissions.Publish.Allow}
	for _, s := range info.PublishAllow {
		if !strings.HasPrefix(s, "$SYS.") {
			info.Code = strings.SplitN(s, ".", 2)[0]
			break
		}
	}
	if info.Code == "" {
		return info, errors.New("no code in the agent's publish grant")
	}
	return info, nil
}

// Publish sends the message and flushes. A permissions violation arrives before the
// flush's PONG, so it is reported here.
func (c *Client) Publish(subject string, data []byte) error {
	if err := c.nc.Publish(subject, data); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if err := c.nc.FlushTimeout(c.timeout); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	if err := c.nc.LastError(); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}
