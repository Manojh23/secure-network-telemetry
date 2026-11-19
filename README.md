# Secure Network Telemetry

A Go backend for collecting connection-health reports from distributed sites. A Python probe measures an explicitly chosen TCP or TLS endpoint; the service accepts signed reports and returns per-site availability and successful-connection p95 latency. This is a small network-operations SaaS prototype, inspired by secure IP service monitoring. It does not implement SIP, a session border controller, or traffic forwarding.

## Run a real local demo

Requires Go 1.26+, Python 3.10+, and OpenSSL. No external Go packages or cloud account are required.

```sh
python3 scripts/dev_setup.py
go run ./cmd/gateway
```

In another terminal, probe the local service and view its summary:

```sh
python3 scripts/probe.py
python3 scripts/probe.py --protocol tcp
# Report a failed connection without contacting an external host:
python3 scripts/probe.py --port 1
```

The client explicitly trusts the generated local certificate; certificate verification stays enabled. All development credentials live under the ignored `.local/` directory. To use Docker Compose, first run setup, then set `LOCAL_UID=$(id -u)` and `LOCAL_GID=$(id -g)` in your environment and run `docker compose up --build`. This keeps the mounted configuration and journal accessible to your non-root user.

## What is implemented

| Component | Behavior |
| --- | --- |
| Go HTTPS service | TLS 1.3 minimum; read/write/header deadlines; bounded concurrent admission; structured request-ID and elapsed-time logs; SIGTERM drains active requests |
| Authentication | HMAC-SHA256 over key ID, method, exact request URI, timestamp, nonce, and SHA256 body digest; constant-time comparison; freshness window; bounded nonce replay cache |
| Tenant isolation | Tenant comes exclusively from server-side credentials. Clients cannot choose another tenant in a report or summary request |
| Durable ingestion | JSON journal with fsync before acknowledgement; advisory exclusive writer lock; same tenant/report ID is idempotent only when the payload matches; different payload returns 409 |
| Connection summary | Group by site, target, and protocol; requested time window; availability counts failed probes, p95 uses successful probes only; flag availability below 95% or p95 above 250ms |
| Probe | Python socket connection and optional verified TLS handshake, three-second timeout; bounded error label; signed report and summary requests |
| Delivery | Non-root, static Go Docker image; hardened Compose configuration; GitHub Actions checks; Linux amd64/arm64 build support; AWS CloudFormation template |

### API and signing

`GET /healthz` is an unauthenticated process-liveness endpoint. It contains no report or tenant information.

`POST /v1/reports` accepts JSON with `id`, `site`, `target`, `protocol` (`tcp` or `tls`), `observed_at` (Unix seconds), `success`, `latency_ms`, and optional `error`. Reports may be at most a day old or 30 seconds in the future. The body is limited to 8 KiB; unknown fields and multiple JSON documents are rejected.

`GET /v1/summary?since=<unix-seconds>` returns only the authenticated tenant's reports, aggregated since that time. The default is the past hour. No measurements returns an empty array, not an assertion that a site is healthy.

Both `/v1` endpoints require `X-Key-ID`, `X-Timestamp`, `X-Nonce`, and `X-Signature`. The exact signature construction is in `gateway.Signature` and `scripts/probe.py`. Retrying a report uses a **fresh nonce** and the **same report ID and payload**. A repeated nonce returns 409. A mismatched signature or expired request returns 401. Saturated request admission returns 503 with `Retry-After: 1`.

Credential JSON format (generate a real random secret; do not use this placeholder):

```json
{"site-key":{"tenant":"demo","secret":"REPLACE_WITH_AT_LEAST_32_RANDOM_BYTES"}}
```

## Verify

```sh
make test
make check
make build
python3 scripts/smoke.py
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/gateway-arm64 ./cmd/gateway
pip install cfn-lint
cfn-lint infra/aws.yaml
```

Go tests cover signed-payload/query tampering, expired requests, replay, tenant isolation, concurrent duplicate writes, journal capacity and exclusive locks, corrupt-journal rejection, recovery after reopening, request backpressure, strict JSON, summary arithmetic, verified TLS 1.3, and TLS 1.2 rejection. The process smoke test exercises the compiled service over HTTPS, terminates it gracefully, restarts it, and verifies persisted reports and idempotency.

## AWS deployment configuration

`infra/aws.yaml` describes one Amazon Linux EC2 instance, an encrypted EBS root volume, CIDR-restricted port 9443, IMDSv2, a narrowly scoped configuration-secret read permission, and ECR image-pull permissions. At boot it retrieves credentials and a matching TLS certificate from Secrets Manager without embedding them in user data, pulls a digest-pinned private ECR image, and runs the non-root container with a persistent journal mount and bounded Docker logs. No SSH port is opened.

Provide an existing VPC/public subnet, trusted client CIDR, image digest, and a Secrets Manager JSON secret with three string fields: `keys_json`, `tls_cert`, and `tls_key`. The certificate must match a DNS name you control. The existing subnet must support outbound package/ECR/Secrets Manager access. A secret encrypted by a customer-managed KMS key also requires a separately scoped `kms:Decrypt` permission.

The template is linted, **not deployed to AWS**. Docker configuration is supplied; the image is not locally executed in the development environment. Applying the template creates billable resources. The EBS journal is deleted when the instance is terminated; arrange backups before relying on it.

## Engineering scope and next steps

- The journal deliberately supports **one writer/one replica**, enforced with a file lock. The 10,000-report cap rejects new records with 503 rather than growing indefinitely. It needs retention/compaction for long-running use. Do not horizontally scale it as-is; move idempotency and storage into PostgreSQL before adding replicas.
- Nonces are memory-resident and reset on restart. A captured request within the remaining freshness window can be reauthenticated after restart; durable report IDs still prevent a duplicate ingestion. Persist nonce state if preventing every authenticated replay across restarts is a requirement.
- Truncated or corrupt journal data causes startup to fail. Preserve the file and inspect/recover it manually; the service does not silently discard data.
- Each key can both submit and read reports for one tenant. There is no interactive login, key-rotation endpoint, fine-grained RBAC, or certified security compliance.
- Probes measure connection establishment and certificate validation, not application availability, packet loss, voice quality, or SLA compliance. Reported metrics are trusted input from an authenticated probe.
- Local tests use loopback endpoints and synthetic site labels. No customer network or live telecom data is used.

## Implementation references

- [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config)
- [Go HTTP server shutdown](https://pkg.go.dev/net/http#Server.Shutdown)
- [AWS EC2 CloudFormation resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html)
- [AWS Secrets Manager access](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access.html)
