package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSecret(t *testing.T, kv map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for k, v := range kv {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func baseSecret() map[string]string {
	return map[string]string{
		"AGENT_KIND":    "backup\n",
		"AGENT_UUID":    " 01a2034e-79ce-7397-b3d0-ac67b916df3c ",
		"NATS_SENTINEL": "eyJ.sentinel.jwt\n",
		"NATS_TENANT":   "01a2034e-4163-7d1d-a7a6-704b04bac5c7",
		"NATS_TOKEN":    "cpa_test",
		"NATS_URLS":     "tls://a:4222,tls://b:4222\n",
	}
}

func TestLoadConfig(t *testing.T) {
	dir := writeSecret(t, baseSecret())
	cfg, err := LoadConfig(dir, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Dir: dir, URLs: "tls://a:4222,tls://b:4222", Tenant: "01a2034e-4163-7d1d-a7a6-704b04bac5c7",
		Sentinel: "eyJ.sentinel.jwt", Kind: "backup", UUID: "01a2034e-79ce-7397-b3d0-ac67b916df3c",
		Timeout: 3 * time.Second,
	}
	if cfg != want {
		t.Fatalf("LoadConfig =\n%+v\nwant\n%+v", cfg, want)
	}
}

func TestLoadConfigCA(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		want  string
	}{
		{"none", nil, ""},
		{"ca.crt", []string{"ca.crt"}, "ca.crt"},
		{"ca.cert", []string{"ca.cert"}, "ca.cert"},
		{"both prefers ca.cert", []string{"ca.cert", "ca.crt"}, "ca.cert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSecret()
			for _, f := range tc.files {
				s[f] = "pem"
			}
			dir := writeSecret(t, s)
			cfg, err := LoadConfig(dir, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.want != "" {
				want = filepath.Join(dir, tc.want)
			}
			if cfg.CAFile != want {
				t.Fatalf("CAFile = %q, want %q", cfg.CAFile, want)
			}
		})
	}
}

func TestLoadConfigMissingKey(t *testing.T) {
	for key := range baseSecret() {
		t.Run(key, func(t *testing.T) {
			s := baseSecret()
			delete(s, key)
			_, err := LoadConfig(writeSecret(t, s), time.Second)
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("want error naming %s, got %v", key, err)
			}
		})
	}
}

func TestParseUserInfo(t *testing.T) {
	for _, tc := range []struct {
		name, in, code, identity, err string
	}{
		{
			name:     "grant",
			in:       `{"data":{"user":"service_account:u","permissions":{"publish":{"allow":["$SYS.REQ.USER.INFO","abc.agent.status","abc.backup.events"]}}}}`,
			code:     "abc",
			identity: "service_account:u",
		},
		{name: "no grant", in: `{"data":{"user":""}}`},
		{name: "server error", in: `{"error":{"code":500,"description":"boom"}}`, err: "boom"},
		{name: "not json", in: `nope`, err: "parse user info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseUserInfo([]byte(tc.in))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("want error %q, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if info.Code != tc.code || info.Identity != tc.identity {
				t.Fatalf("got code=%q identity=%q", info.Code, info.Identity)
			}
		})
	}
}

func TestServiceError(t *testing.T) {
	e := &ServiceError{Code: "422", Description: "the message does not match its schema"}
	if got := e.Error(); got != "platform refused the event: 422 the message does not match its schema" {
		t.Fatalf("Error() = %q", got)
	}
}
