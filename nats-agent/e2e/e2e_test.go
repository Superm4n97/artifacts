// Package e2e runs the built nats-agent binary against an in-process TLS nats-server
// whose auth callout checks every credential the platform checks: the sentinel JWT, the
// tenant as user, the inbox public key as password with a signed nonce, and the token.
// The callout grants the agent <code>.<kind>.events and $SYS.REQ.USER.INFO, like the
// platform does, so the code comes from the server and publishing outside the grant is
// refused by the server.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const (
	tenant = "01a2034e-4163-7d1d-a7a6-704b04bac5c7"
	uuid   = "01a2034e-79ce-7397-b3d0-ac67b916df3c"
	token  = "cpa_e2e_token"
	// code is the platform's code for service_account:<uuid>, written out so the test
	// does not reuse the CLI's own computation.
	code = "s5vjhdqq2ke3fuohnhtpolcyjq"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nats-agent-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin = filepath.Join(dir, "nats-agent")
	build := exec.Command("go", "build", "-o", bin, "..")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build nats-agent:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	rc := m.Run()
	os.RemoveAll(dir)
	os.Exit(rc)
}

// grant is what the callout gives a connection that passes every check.
type grant struct {
	code string // first token of the publish grant; empty: the default code
	kind string // <code>.<kind>.events; empty: backup
}

type env struct {
	t        *testing.T
	s        *server.Server
	caPEM    []byte
	authAcc  nkeys.KeyPair // AUTH account: runs the callout, issues sentinels
	appAcc   nkeys.KeyPair // APP account: where agents and the platform live
	sentinel string
}

func mustKey(t *testing.T, create func() (nkeys.KeyPair, error)) (nkeys.KeyPair, string) {
	t.Helper()
	kp, err := create()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return kp, pub
}

func mustEncode(t *testing.T, c interface {
	Encode(nkeys.KeyPair) (string, error)
}, kp nkeys.KeyPair) string {
	t.Helper()
	s, err := c.Encode(kp)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// start runs an operator-mode server (as the platform does: outside operator mode the
// server drops the client's JWT) and the auth callout service for one test.
func start(t *testing.T, g grant) *env {
	t.Helper()
	if g.code == "" {
		g.code = code
	}
	if g.kind == "" {
		g.kind = "backup"
	}
	tlsCfg, caPEM := tlsCert(t)

	op, opPub := mustKey(t, nkeys.CreateOperator)
	_, sysPub := mustKey(t, nkeys.CreateAccount)
	authAcc, authPub := mustKey(t, nkeys.CreateAccount)
	appAcc, appPub := mustKey(t, nkeys.CreateAccount)
	calloutUser, calloutPub := mustKey(t, nkeys.CreateUser)

	oc := jwt.NewOperatorClaims(opPub)
	oc.SystemAccount = sysPub
	mustEncode(t, oc, op) // sets the issuer

	resolver := &server.MemAccResolver{}
	sysClaims := jwt.NewAccountClaims(sysPub)
	sysClaims.Name = "SYS"
	authClaims := jwt.NewAccountClaims(authPub)
	authClaims.Name = "AUTH"
	authClaims.Authorization.AuthUsers.Add(calloutPub)
	authClaims.Authorization.AllowedAccounts.Add(appPub)
	appClaims := jwt.NewAccountClaims(appPub)
	appClaims.Name = "APP"
	for pub, ac := range map[string]*jwt.AccountClaims{sysPub: sysClaims, authPub: authClaims, appPub: appClaims} {
		if err := resolver.Store(pub, mustEncode(t, ac, op)); err != nil {
			t.Fatal(err)
		}
	}

	s, err := server.NewServer(&server.Options{
		Host:             "127.0.0.1",
		Port:             server.RANDOM_PORT,
		NoLog:            true,
		NoSigs:           true,
		TLS:              true,
		TLSConfig:        tlsCfg,
		TLSTimeout:       2,
		TrustedOperators: []*jwt.OperatorClaims{oc},
		SystemAccount:    sysPub,
		AccountResolver:  resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(s.Shutdown)
	e := &env{t: t, s: s, caPEM: caPEM, authAcc: authAcc, appAcc: appAcc}
	e.sentinel = e.newSentinel()

	nc := e.conn(authAcc, calloutUser)
	_, err = nc.Subscribe("$SYS.REQ.USER.AUTH", func(m *nats.Msg) {
		rc, err := jwt.DecodeAuthorizationRequestClaims(string(m.Data))
		if err != nil {
			t.Errorf("callout: decode request: %v", err)
			return
		}
		resp := jwt.NewAuthorizationResponseClaims(rc.UserNkey)
		resp.Audience = rc.Server.ID
		if err := check(rc, e.sentinel); err != nil {
			t.Logf("callout: deny: %v", err)
			resp.Error = err.Error()
		} else {
			uc := jwt.NewUserClaims(rc.UserNkey)
			uc.Name = "service_account:" + uuid
			uc.Pub.Allow.Add(g.code+"."+g.kind+".events", "$SYS.REQ.USER.INFO")
			uc.Sub.Allow.Add("_INBOX." + rc.ConnectOptions.Password + ".>")
			if resp.Jwt, err = uc.Encode(appAcc); err != nil {
				t.Errorf("callout: encode user: %v", err)
				return
			}
		}
		out, err := resp.Encode(authAcc)
		if err != nil {
			t.Errorf("callout: encode response: %v", err)
			return
		}
		_ = m.Respond([]byte(out))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return e
}

// newSentinel mints a bearer user JWT in the AUTH account with no permissions. It only
// gets a connection to the callout; the callout decides the real user.
func (e *env) newSentinel() string {
	e.t.Helper()
	_, pub := mustKey(e.t, nkeys.CreateUser)
	uc := jwt.NewUserClaims(pub)
	uc.BearerToken = true
	uc.Pub.Deny.Add(">")
	uc.Sub.Deny.Add(">")
	return mustEncode(e.t, uc, e.authAcc)
}

// check is the platform's credential check.
func check(rc *jwt.AuthorizationRequestClaims, sentinel string) error {
	o := rc.ConnectOptions
	switch {
	case o.Token != token:
		return errors.New("bad token")
	case o.JWT != sentinel:
		return errors.New("bad sentinel")
	case o.Username != tenant:
		return errors.New("bad tenant")
	case !strings.HasPrefix(o.Password, "U"):
		return errors.New("password is not an inbox user public key")
	}
	inbox, err := nkeys.FromPublicKey(o.Password)
	if err != nil {
		return fmt.Errorf("inbox key: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(o.SignedNonce)
	if err != nil || rc.ClientInformation.Nonce == "" {
		return errors.New("no signed nonce")
	}
	if err := inbox.Verify([]byte(rc.ClientInformation.Nonce), sig); err != nil {
		return errors.New("nonce not signed by the inbox key")
	}
	return nil
}

// conn connects a service user issued by account.
func (e *env) conn(account, user nkeys.KeyPair) *nats.Conn {
	e.t.Helper()
	pub, _ := user.PublicKey()
	ujwt := mustEncode(e.t, jwt.NewUserClaims(pub), account)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	nc, err := nats.Connect(e.s.ClientURL(),
		nats.UserJWT(func() (string, error) { return ujwt, nil }, user.Sign),
		nats.Secure(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(nc.Close)
	return nc
}

// platform answers requests on subject with header, and hands each request to the test.
func (e *env) platform(subject string, header nats.Header) chan *nats.Msg {
	e.t.Helper()
	user, _ := mustKey(e.t, nkeys.CreateUser)
	nc := e.conn(e.appAcc, user)
	got := make(chan *nats.Msg, 4)
	if _, err := nc.Subscribe(subject, func(m *nats.Msg) {
		got <- m
		_ = m.RespondMsg(&nats.Msg{Header: header, Data: []byte("{}")})
	}); err != nil {
		e.t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		e.t.Fatal(err)
	}
	return got
}

// secret writes the agent Secret as the kubelet mounts it, with overrides.
func (e *env) secret(override map[string]string) string {
	e.t.Helper()
	dir := e.t.TempDir()
	files := map[string]string{
		"AGENT_KIND":    "backup",
		"AGENT_UUID":    uuid,
		"NATS_SENTINEL": e.sentinel,
		"NATS_TENANT":   tenant,
		"NATS_TOKEN":    token + "\n",
		"NATS_URLS":     fmt.Sprintf("tls://127.0.0.1:%d", e.s.Addr().(*net.TCPAddr).Port),
		"ca.crt":        string(e.caPEM),
	}
	maps.Copy(files, override)
	for k, v := range files {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			e.t.Fatal(err)
		}
	}
	return dir
}

type result struct {
	stdout, stderr string
	err            error
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return result{out.String(), errOut.String(), err}
}

func publishArgs(dir string) []string {
	return []string{
		"publish", "--secret-dir", dir, "--timeout", "3s",
		"--backupSessionName", "bs-1",
		"--backupSessionNamespace", "demo",
		"--backupConfigurationName", "bc-1",
		"--message", "backup done",
		"--phase", "Succeeded",
	}
}

func recv(t *testing.T, got chan *nats.Msg) *nats.Msg {
	t.Helper()
	select {
	case m := <-got:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("platform got nothing")
		return nil
	}
}

func TestWhoami(t *testing.T) {
	e := start(t, grant{})
	r := run(t, "whoami", "--secret-dir", e.secret(nil), "--timeout", "3s")
	if r.err != nil {
		t.Fatalf("whoami: %v\n%s", r.err, r.stderr)
	}
	for _, want := range []string{
		fmt.Sprintf("code:     %s (computed %s)", code, code),
		code + ".backup.events",
		"$SYS.REQ.USER.INFO",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, r.stdout)
		}
	}
}

func TestPublish(t *testing.T) {
	e := start(t, grant{})
	got := e.platform(code+".backup.events", nil)
	before := time.Now().UTC().Add(-time.Second)

	r := run(t, publishArgs(e.secret(nil))...)
	if r.err != nil {
		t.Fatalf("publish: %v\n%s", r.err, r.stderr)
	}
	m := recv(t, got)

	if m.Header.Get("Nats-Msg-Id") == "" {
		t.Error("no Nats-Msg-Id header")
	}
	if v := m.Header.Get("schema-version"); v != "v1" {
		t.Errorf("schema-version = %q", v)
	}
	var ev map[string]any
	if err := json.Unmarshal(m.Data, &ev); err != nil {
		t.Fatalf("body is not JSON: %v: %s", err, m.Data)
	}
	want := map[string]any{
		"backupSessionName":       "bs-1",
		"backupSessionNamespace":  "demo",
		"backupConfigurationName": "bc-1",
		"message":                 "backup done",
		"phase":                   "Succeeded",
		"kind":                    "backup",
		"uuid":                    uuid,
	}
	for k, v := range want {
		if ev[k] != v {
			t.Errorf("%s = %v, want %v", k, ev[k], v)
		}
	}
	ts, err := time.Parse(time.RFC3339Nano, fmt.Sprint(ev["time"]))
	if err != nil || ts.Before(before) || ts.After(time.Now().Add(time.Second)) || ts.Location() != time.UTC {
		t.Errorf("time = %v (%v)", ev["time"], err)
	}
	if len(ev) != len(want)+1 {
		t.Errorf("unexpected fields in %s", m.Data)
	}
	if strings.TrimSpace(r.stdout) != string(m.Data) {
		t.Errorf("stdout %q != published %q", r.stdout, m.Data)
	}
	for _, secret := range []string{token, e.sentinel} {
		if strings.Contains(string(m.Data), secret) || strings.Contains(r.stdout+r.stderr, secret) {
			t.Errorf("%q leaked", secret)
		}
	}
}

// The server's grant decides the subject, even when it differs from the computed code.
func TestPublishUsesServerCode(t *testing.T) {
	const other = "zzzzzzzzzzzzzzzzzzzzzzzzzz"
	e := start(t, grant{code: other})
	got := e.platform(other+".backup.events", nil)

	r := run(t, publishArgs(e.secret(nil))...)
	if r.err != nil {
		t.Fatalf("publish: %v\n%s", r.err, r.stderr)
	}
	recv(t, got)
	if !strings.Contains(r.stderr, "differs from computed") {
		t.Errorf("no code mismatch warning:\n%s", r.stderr)
	}
}

func TestPublishRefusedByPlatform(t *testing.T) {
	e := start(t, grant{})
	e.platform(code+".backup.events", nats.Header{
		"Nats-Service-Error-Code": []string{"422"},
		"Nats-Service-Error":      []string{"the message does not match its schema"},
	})
	r := run(t, publishArgs(e.secret(nil))...)
	if exitCode(r.err) != 1 {
		t.Fatalf("exit = %v, want 1\n%s", r.err, r.stderr)
	}
	if !strings.Contains(r.stderr, "platform refused the event: 422 the message does not match its schema") {
		t.Errorf("stderr:\n%s", r.stderr)
	}
	if r.stdout != "" {
		t.Errorf("stdout on failure: %q", r.stdout)
	}
}

// AGENT_KIND=restore publishes on <code>.restore.events, which the grant does not allow.
func TestPublishOutsideGrant(t *testing.T) {
	e := start(t, grant{})
	r := run(t, publishArgs(e.secret(map[string]string{"AGENT_KIND": "restore"}))...)
	if exitCode(r.err) != 1 {
		t.Fatalf("exit = %v, want 1\n%s", r.err, r.stderr)
	}
	if !strings.Contains(strings.ToLower(r.stderr), "permissions violation") {
		t.Errorf("want permissions violation:\n%s", r.stderr)
	}
}

func TestNoPlatform(t *testing.T) {
	e := start(t, grant{})
	r := run(t, publishArgs(e.secret(nil))...)
	if exitCode(r.err) != 1 || !strings.Contains(r.stderr, "no responders") {
		t.Fatalf("want no responders, got %v\n%s", r.err, r.stderr)
	}
}

func TestAuthRejected(t *testing.T) {
	e := start(t, grant{})
	for name, override := range map[string]map[string]string{
		"wrong token":    {"NATS_TOKEN": "cpa_wrong"},
		"wrong sentinel": {"NATS_SENTINEL": e.newSentinel()},
		"bogus sentinel": {"NATS_SENTINEL": "eyJ.not.a.jwt"},
		"wrong tenant":   {"NATS_TENANT": "other-tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, "whoami", "--secret-dir", e.secret(override), "--timeout", "3s")
			if exitCode(r.err) != 1 || !strings.Contains(strings.ToLower(r.stderr), "authorization violation") {
				t.Fatalf("want authorization violation, got %v\n%s", r.err, r.stderr)
			}
		})
	}
}

// Whitespace around the token is trimmed, and the CA may be named ca.cert.
func TestTokenTrailingNewlineAndCAFileName(t *testing.T) {
	e := start(t, grant{})
	dir := e.secret(map[string]string{"NATS_TOKEN": "\n" + token + "\n\n"})
	if err := os.Rename(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.cert")); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "whoami", "--secret-dir", dir, "--timeout", "3s"); r.err != nil {
		t.Fatalf("whoami: %v\n%s", r.err, r.stderr)
	}
}

func TestUntrustedCA(t *testing.T) {
	e := start(t, grant{})
	_, otherCA := tlsCert(t)
	r := run(t, "whoami", "--secret-dir", e.secret(map[string]string{"ca.crt": string(otherCA)}), "--timeout", "3s")
	if exitCode(r.err) != 1 || !strings.Contains(r.stderr, "certificate") {
		t.Fatalf("want TLS certificate error, got %v\n%s", r.err, r.stderr)
	}
}

func TestMissingSecretKey(t *testing.T) {
	e := start(t, grant{})
	dir := e.secret(nil)
	if err := os.Remove(filepath.Join(dir, "NATS_SENTINEL")); err != nil {
		t.Fatal(err)
	}
	r := run(t, publishArgs(dir)...)
	if exitCode(r.err) != 1 || !strings.Contains(r.stderr, "NATS_SENTINEL") {
		t.Fatalf("want missing NATS_SENTINEL, got %v\n%s", r.err, r.stderr)
	}
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

// tlsCert makes a self-signed cert for 127.0.0.1 and returns the server's TLS config and
// the PEM to put in the Secret as the CA.
func tlsCert(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "e2e-nats"},
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
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, certPEM
}
