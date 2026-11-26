package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/Superm4n97/artifacts/nats-agent/pkg/agent"
	"github.com/Superm4n97/artifacts/nats-agent/pkg/event"
)

const (
	testToken = "cpa_test_token"
	testUUID  = "01a2034e-79ce-7397-b3d0-ac67b916df3c"
	testCode  = "s5vjhdqq2ke3fuohnhtpolcyjq"
)

var publishArgs = []string{
	"--backupSessionName", "bs-1",
	"--backupSessionNamespace", "demo",
	"--backupConfigurationName", "bc-1",
	"--message", "backup done",
	"--phase", "Succeeded",
}

// tlsCert makes a self-signed CA-capable cert for 127.0.0.1 and returns the server's
// TLS config and the PEM to put in the Secret as ca.crt.
func tlsCert(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-nats"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, certPEM
}

// startServer runs an in-process TLS nats-server with token auth. It has no auth
// callout, so it ignores the sentinel and user/pass and grants no code: the CLI falls
// back to the code computed from AGENT_UUID.
func startServer(t *testing.T) (*server.Server, []byte) {
	t.Helper()
	tlsCfg, caPEM := tlsCert(t)
	s, err := server.NewServer(&server.Options{
		Host:          "127.0.0.1",
		Port:          server.RANDOM_PORT,
		NoLog:         true,
		NoSigs:        true,
		Authorization: testToken,
		TLS:           true,
		TLSConfig:     tlsCfg,
		TLSTimeout:    2,
	})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(s.Shutdown)
	return s, caPEM
}

func secretDir(t *testing.T, s *server.Server, caPEM []byte, token string) string {
	t.Helper()
	dir := t.TempDir()
	url := fmt.Sprintf("tls://127.0.0.1:%d", s.Addr().(*net.TCPAddr).Port)
	for k, v := range map[string]string{
		"AGENT_KIND":    "backup",
		"AGENT_UUID":    testUUID,
		"NATS_SENTINEL": "eyJ.sentinel.jwt",
		"NATS_TENANT":   "01a2034e-4163-7d1d-a7a6-704b04bac5c7",
		"NATS_TOKEN":    token + "\n",
		"NATS_URLS":     url,
		"ca.crt":        string(caPEM),
	} {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// platform subscribes as the ingress would and answers each event with header.
func platform(t *testing.T, s *server.Server, caPEM []byte, header nats.Header) chan *nats.Msg {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	nc, err := nats.Connect(s.ClientURL(), nats.Token(testToken),
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	got := make(chan *nats.Msg, 4)
	_, err = nc.Subscribe(event.Subject(testCode, "backup"), func(m *nats.Msg) {
		got <- m
		_ = m.RespondMsg(&nats.Msg{Header: header, Data: []byte("{}")})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return got
}

func run(args ...string) (string, error) {
	root := NewRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String() + errOut.String(), err
}

func TestPublish(t *testing.T) {
	fixed := time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)
	now = func() time.Time { return fixed }
	t.Cleanup(func() { now = time.Now })

	s, caPEM := startServer(t)
	got := platform(t, s, caPEM, nil)
	dir := secretDir(t, s, caPEM, testToken)

	out, err := run(append([]string{"publish", "--secret-dir", dir, "--timeout", "3s"}, publishArgs...)...)
	if err != nil {
		t.Fatalf("publish: %v\n%s", err, out)
	}

	var m *nats.Msg
	select {
	case m = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("platform got nothing")
	}
	if m.Subject != testCode+".backup.events" {
		t.Errorf("subject = %q", m.Subject)
	}
	if m.Header.Get("Nats-Msg-Id") == "" {
		t.Error("no Nats-Msg-Id header")
	}
	var ev event.Backup
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		t.Fatal(err)
	}
	want := event.Backup{
		BackupSessionName: "bs-1", BackupSessionNamespace: "demo", BackupConfigurationName: "bc-1",
		Message: "backup done", Phase: "Succeeded", Kind: "backup", UUID: testUUID, Time: fixed,
	}
	if ev != want {
		t.Errorf("event =\n%+v\nwant\n%+v", ev, want)
	}
	if !strings.Contains(out, `"backupSessionName":"bs-1"`) {
		t.Errorf("stdout lacks the event: %s", out)
	}
}

func TestPublishRefused(t *testing.T) {
	s, caPEM := startServer(t)
	platform(t, s, caPEM, nats.Header{
		"Nats-Service-Error-Code": []string{"422"},
		"Nats-Service-Error":      []string{"the message does not match its schema"},
	})
	dir := secretDir(t, s, caPEM, testToken)

	_, err := run(append([]string{"publish", "--secret-dir", dir, "--timeout", "3s"}, publishArgs...)...)
	var se *agent.ServiceError
	if err == nil || !asServiceError(err, &se) || se.Code != "422" {
		t.Fatalf("want 422 ServiceError, got %v", err)
	}
}

func TestPublishNoResponders(t *testing.T) {
	s, caPEM := startServer(t)
	dir := secretDir(t, s, caPEM, testToken)
	_, err := run(append([]string{"publish", "--secret-dir", dir, "--timeout", "2s"}, publishArgs...)...)
	if err == nil || !strings.Contains(err.Error(), "no responders") {
		t.Fatalf("want no responders, got %v", err)
	}
}

func TestPublishBadToken(t *testing.T) {
	s, caPEM := startServer(t)
	dir := secretDir(t, s, caPEM, "cpa_wrong")
	_, err := run(append([]string{"publish", "--secret-dir", dir, "--timeout", "2s"}, publishArgs...)...)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "authorization violation") {
		t.Fatalf("want authorization violation, got %v", err)
	}
}

func TestWhoami(t *testing.T) {
	s, caPEM := startServer(t)
	dir := secretDir(t, s, caPEM, testToken)
	out, err := run("whoami", "--secret-dir", dir, "--timeout", "3s")
	if err != nil {
		t.Fatalf("whoami: %v\n%s", err, out)
	}
	if !strings.Contains(out, "computed "+testCode) {
		t.Fatalf("whoami output: %s", out)
	}
}

func TestPublishFlags(t *testing.T) {
	dir := t.TempDir() // never read: flag errors come first
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"all missing", []string{"publish", "--secret-dir", dir},
			`required flag(s) "backupConfigurationName", "backupSessionName", "backupSessionNamespace", "message", "phase" not set`},
		{"one missing", append([]string{"publish", "--secret-dir", dir}, publishArgs[:8]...),
			`required flag(s) "phase" not set`},
		{"empty value", append(append([]string{"publish", "--secret-dir", dir}, publishArgs[:8]...), "--phase", " "),
			"empty value for: phase"},
		{"subject-suffix removed", append([]string{"publish", "--subject-suffix", "x"}, publishArgs...),
			"unknown flag: --subject-suffix"},
		{"asJSON removed", append([]string{"publish", "--asJSON"}, publishArgs...),
			"unknown flag: --asJSON"},
		{"no positional args", append([]string{"publish", "extra"}, publishArgs...),
			`unknown command "extra"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPublishMissingSecret(t *testing.T) {
	_, err := run(append([]string{"publish", "--secret-dir", t.TempDir()}, publishArgs...)...)
	if err == nil || !strings.Contains(err.Error(), "NATS_") && !strings.Contains(err.Error(), "AGENT_") {
		t.Fatalf("want missing key error, got %v", err)
	}
}

func asServiceError(err error, target **agent.ServiceError) bool {
	return errors.As(err, target)
}
