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

### Global flags

| Flag | Default | Meaning |
|---|---|---|
| `--secret-dir` | `/etc/nats-agent` | Directory where the agent Secret is mounted, one file per key. |
| `--timeout` | `10s` | Connect and request timeout. |

Every command connects the same way: a fresh inbox nkey signs the sentinel JWT, the
tenant and inbox public key go as user/password, and `NATS_TOKEN` goes as the token.
`NATS_TOKEN` is re-read from disk on every (re)connect, so a rotated token is picked up.
If `ca.cert` or `ca.crt` exists it is used as the root CA; otherwise system roots.

### `whoami`

Connects and prints who the server thinks this agent is. Use it to check that the
Secret works and to see which subjects the agent may publish to before you publish.

```sh
nats-agent whoami --secret-dir /etc/nats-agent
```

```
identity: <user from the auth callout>
code:     dc-abc123
publish:  [dc-abc123.> ...]
```

- `identity`: the user the auth callout assigned.
- `code`: the agent's subject namespace. Not in the Secret; taken from the first
  non-`$SYS` publish grant returned by `$SYS.REQ.USER.INFO`.
- `publish`: the full publish allow list.

### `publish`

Connects, learns the agent's code as `whoami` does, and publishes one message on
`<code>.<subject-suffix>`. It flushes and checks for a server error, so a permissions
violation is reported as a failure, not dropped silently.

| Flag | Default | Meaning |
|---|---|---|
| `--subject-suffix` | `agent.status` | Subject after the code. Must be inside the agent's publish grant (see `whoami`). |
| `--message` | `my-kind: <AGENT_KIND>, my-uuid: <AGENT_UUID>` | Raw message body. |
| `--json` | off | Send a JSON object instead (see below). Cannot be combined with `--message`. |

You only choose the suffix, so a message can never leave the agent's own namespace.

```sh
# default body on <code>.agent.status
nats-agent publish --secret-dir /etc/nats-agent

# custom text on <code>.agent.status
nats-agent publish --subject-suffix agent.status --message 'hello'

# JSON status on <code>.agent.status
nats-agent publish --json
```

`--json` body:

```json
{"kind":"<AGENT_KIND>","uuid":"<AGENT_UUID>","tenant":"<NATS_TENANT>","code":"dc-abc123","identity":"<identity>","time":"2026-11-24T10:00:00Z"}
```

`--json` sends only non-secret fields; `NATS_TOKEN`, `NATS_SENTINEL` and the CA are never
included. Do not put them in `--message` either: every subscriber on the subject would
receive them.

Typical uses: smoke-test the Secret, auth callout and grants end to end; send a
heartbeat/status from a Job or CronJob. To watch messages arrive, subscribe on the
backend side, for example `nats sub 'dc-abc123.agent.status'`.

## Release

Push a tag `nats-agent/vX.Y.Z`; `.github/workflows/nats-agent-release.yml` builds the
binaries and attaches them to a GitHub release.

```sh
git tag nats-agent/v0.0.1 && git push origin nats-agent/v0.0.1
```

`examples/job.yaml` runs it as a Kubernetes Job on the `nats` image.
