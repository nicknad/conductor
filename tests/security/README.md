# DAST container scan

Runs the real release binary in a container, behind its TLS-only listener,
and points OWASP ZAP's API scan at it. The OpenAPI document enumerates
`GET /healthz`, `GET /readyz`, `POST /v1/packages`, `POST /v1/modules/{module_id}/activate`,
`POST /v1/modules/{module_id}/executions`, `GET /v1/executions`, and
`GET /v1/executions/{execution_id}`, and ZAP's auth-header environment
variables attach the operator bearer to every generated request. The scan
exercises the authenticated upload path, the activation/execution auth and
refusal paths, and the read-only execution-history auth and validation paths.
It does not execute a worker: no module is seeded in the container, so a
generated execution request reaches the not-found path rather than a spawned
process.

## Run

```sh
tests/security/scan.sh
```

Requires Docker (or Podman with its Docker Compose provider) and `openssl`.
The script generates a throwaway TLS identity and bearer token under
`tests/security/generated/`, builds the image from the repository root, and
runs the scan. Reports are written to `tests/security/out/`
(`api-scan.html`, `api-scan.json`, `api-scan.md`).

Both generated directories are gitignored; no key material or scan output is
committed.

## CI

`.github/workflows/dast.yml` runs the same script on API/security-relevant
pull requests and weekly on a schedule, and uploads the reports as artifacts.
A FAIL-level ZAP rule (for example a missing security header or an
application error disclosure) fails the job; ordinary warnings are reported
but do not block, matching `-I`.

## Rule policy

`zap-rules.conf` is passed with `-c`. Required transport headers (HSTS,
`X-Frame-Options`, `X-Content-Type-Options`, CORP) are `FAIL`, so a regression
that drops one fails the scan. Rules that are intentional for an authenticated,
non-cacheable JSON API (cache/storability and the 404-on-root notice) are
`IGNORE`; all other ZAP rules stay at their defaults and are reported without
blocking because the scan uses `-I`.
