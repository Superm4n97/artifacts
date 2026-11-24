# nats-agent

Small CLI that connects to the platform NATS servers with a datacenter agent Secret
(`NATS_URLS`, `NATS_TENANT`, `NATS_TOKEN`, `NATS_SENTINEL`, `AGENT_KIND`, `AGENT_UUID`,
`ca.cert`/`ca.crt`) mounted as files.

The stock `nats` CLI cannot do this: it sends only one of creds, user/password or token,
while the auth callout needs the sentinel JWT (signed by an inbox key), the tenant and
inbox public key as user/password, and the token, all in one CONNECT.

## Install

```sh
VERSION=v0.1.0
curl -fsSL -o nats-agent \
  "https://github.com/Superm4n97/helm-artifacts/releases/download/nats-agent/${VERSION}/nats-agent-linux-amd64"
chmod +x nats-agent
```

Assets: `nats-agent-{linux,darwin}-{amd64,arm64}` and `SHA256SUMS`.

## Use

```sh
nats-agent whoami  --secret-dir /etc/nats-agent
nats-agent publish --secret-dir /etc/nats-agent                    # 'my-kind: <kind>, my-uuid: <uuid>' on <code>.agent.status
nats-agent publish --subject-suffix agent.status --message 'hello'
```

The agent's code is learned from `$SYS.REQ.USER.INFO`. Publishing outside the agent's
grant fails with a permissions violation.

## Release

Push a tag `nats-agent/vX.Y.Z`; `.github/workflows/nats-agent-release.yml` builds the
binaries and attaches them to a GitHub release.

```sh
git tag nats-agent/v0.1.0 && git push origin nats-agent/v0.1.0
```

`examples/job.yaml` runs it as a Kubernetes Job on the `nats` image.
