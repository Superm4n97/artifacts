// Package agent connects to the platform NATS servers the way a datacenter agent does:
// sentinel JWT signed by a per-process inbox key, tenant as user, inbox public key as
// password, and the bearer token as auth_token (re-read from disk on every connect).
package agent

import (
	"encoding/json"
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
	Identity     string   `json:"user"`
	PublishAllow []string `json:"-"`
	Code         string   `json:"-"`
}

// UserInfo asks the server who this connection is.
func (c *Client) UserInfo() (UserInfo, error) {
	msg, err := c.nc.Request("$SYS.REQ.USER.INFO", nil, c.timeout)
	if err != nil {
		return UserInfo{}, fmt.Errorf("user info: %w", err)
	}
	return ParseUserInfo(msg.Data)
}

// ParseUserInfo parses a $SYS.REQ.USER.INFO answer. The code is the first token of the
// first publish grant that is not a $SYS subject; it is empty when there is none.
func ParseUserInfo(data []byte) (UserInfo, error) {
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
	if err := json.Unmarshal(data, &resp); err != nil {
		return UserInfo{}, fmt.Errorf("parse user info: %w", err)
	}
	if resp.Error != nil {
		return UserInfo{}, fmt.Errorf("user info: %s", resp.Error.Description)
	}
	info := UserInfo{Identity: resp.Data.User, PublishAllow: resp.Data.Permissions.Publish.Allow}
	for _, s := range info.PublishAllow {
		if s != "" && !strings.HasPrefix(s, "$SYS.") {
			info.Code = strings.SplitN(s, ".", 2)[0]
			break
		}
	}
	return info, nil
}

// ServiceError is a refusal from the platform, carried in the reply's
// Nats-Service-Error-Code and Nats-Service-Error headers.
type ServiceError struct {
	Code        string
	Description string
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("platform refused the event: %s %s", e.Code, e.Description)
}

// Request sends data with headers on subject and waits for the platform's answer. An
// answer with Nats-Service-Error-Code is returned as a *ServiceError. A subject outside
// the grant gets no answer; the server's permissions violation is returned instead of
// the timeout when it has arrived.
func (c *Client) Request(subject string, data []byte, header nats.Header) (*nats.Msg, error) {
	msg := &nats.Msg{Subject: subject, Data: data, Header: header}
	reply, err := c.nc.RequestMsg(msg, c.timeout)
	if err != nil {
		if last := c.nc.LastError(); last != nil {
			return nil, fmt.Errorf("request %s: %w", subject, last)
		}
		return nil, fmt.Errorf("request %s: %w", subject, err)
	}
	if code := reply.Header.Get("Nats-Service-Error-Code"); code != "" {
		return reply, &ServiceError{Code: code, Description: reply.Header.Get("Nats-Service-Error")}
	}
	return reply, nil
}
