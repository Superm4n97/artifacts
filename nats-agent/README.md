# nats-agent

Small CLI that connects to the platform NATS servers with a datacenter agent Secret
(`NATS_URLS`, `NATS_TENANT`, `NATS_TOKEN`, `NATS_SENTINEL`, `AGENT_KIND`, `AGENT_UUID`,
`ca.cert`/`ca.crt`) mounted as files.

The stock `nats` CLI cannot do this: it sends only one of creds, user/password or token,
while the auth callout needs the sentinel JWT (signed by an inbox key), the tenant and
inbox public key as user/password, and the token, all in one CONNECT.

## Install

```sh
VERSION=v0.0.1
curl -fsSL -o nats-agent \
  "https://github.com/Superm4n97/helm-artifacts/releases/download/nats-agent/${VERSION}/nats-agent-linux-amd64"
chmod +x nats-agent
```

Assets: `nats-agent-{linux,darwin}-{amd64,arm64}` and `SHA256SUMS`.

## Use

```sh
nats-agent whoami --secret-dir /etc/nats-agent

nats-agent publish --secret-dir /etc/nats-agent \
  --backupSessionName bs-1 --backupSessionNamespace demo \
  --backupConfigurationName bc-1 --phase Succeeded --message 'backup done'
```

All five `publish` flags are required. It sends this JSON as a request on
`<code>.<AGENT_KIND>.events` (e.g. `<code>.backup.events`) and waits for the platform's
answer; a `Nats-Service-Error-Code` in the answer is an error (non-zero exit):

```json
{
  "backupSessionName": "bs-1",
  "backupSessionNamespace": "demo",
  "backupConfigurationName": "bc-1",
  "message": "backup done",
  "phase": "Succeeded",
  "kind": "backup",
  "uuid": "<AGENT_UUID>",
  "time": "2026-11-25T13:00:00Z"
}
```

`<code>` comes from the server's `$SYS.REQ.USER.INFO` answer, or is computed from
`AGENT_UUID` when the server grants none. The server refuses a subject without the code.

## Test

```sh
go test -race ./...
```

`cmd` tests run the cobra commands against an in-process TLS nats-server.

`e2e` tests build the `nats-agent` binary and run it against an in-process TLS
nats-server in operator mode with an auth callout. The callout checks what the platform
checks (the sentinel bearer JWT, the tenant as user, the inbox public key as password
with the signed nonce, and the token) and grants `<code>.<kind>.events` and
`$SYS.REQ.USER.INFO`. They cover whoami, a successful publish, the server's code taking
precedence, a platform refusal (422), publishing outside the grant, no responders,
rejected credentials, an untrusted CA, and a missing Secret key.

```sh
go test ./e2e/
```

## Release

Push a tag `nats-agent/vX.Y.Z`; `.github/workflows/nats-agent-release.yml` builds the
binaries and attaches them to a GitHub release.

```sh
git tag nats-agent/v0.0.1 && git push origin nats-agent/v0.0.1
```

`examples/job.yaml` runs it as a Kubernetes Job on the `nats` image.
