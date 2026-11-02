#!/usr/bin/env bash
# Build the real conductor image, start it with a self-signed TLS identity,
# and run OWASP ZAP's API scan against it. Reports land in tests/security/out.
#
# Usage: tests/security/scan.sh
# Requires: docker (or podman with the docker-compose provider) and openssl.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
generated="$here/generated"
out="$here/out"
# The compose file uses absolute host paths so Docker Compose and Podman
# Compose resolve the fixture mounts identically.
export DAST_DIR="$here"

if [ -z "${CONDUCTOR_API_TOKEN:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    CONDUCTOR_API_TOKEN="$(openssl rand -hex 32)"
  else
    CONDUCTOR_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  fi
fi
export CONDUCTOR_API_TOKEN

rm -rf "$generated" "$out"
mkdir -p "$generated/tls" "$out"

# ZAP does not validate server certificates, but generating a real identity
# keeps the scanned listener on the same TLS path production uses.
if command -v openssl >/dev/null 2>&1; then
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$generated/tls/key.pem" \
    -out "$generated/tls/cert.pem" \
    -days 1 -subj "/CN=conductor" \
    -addext "subjectAltName=DNS:conductor,DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
else
  # Some hosts (including minimal CI images) lack the openssl CLI; use
  # Python's cryptography package when available.
  python3 - "$generated/tls" <<'PY'
import datetime
import ipaddress
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

out = pathlib.Path(sys.argv[1])
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conductor")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=1))
    .not_valid_after(now + datetime.timedelta(days=1))
    .add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName("conductor"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]
        ),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)
(out / "key.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
)
(out / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
PY
fi

# Static trusted key for the fixture; the scan never uploads a valid signed
# package, so any well-formed Ed25519 public key is sufficient.
cat >"$generated/config.json" <<JSON
{
  "http_bind": "0.0.0.0:8443",
  "storage_root": "/data",
  "request_timeout_secs": 360,
  "tls_cert_path": "/tls/cert.pem",
  "tls_key_path": "/tls/key.pem",
  "max_concurrent_uploads": 8,
  "api_token": "$CONDUCTOR_API_TOKEN",
  "trusted_keys": [{
    "key_id": "scan-key",
    "algorithm": "ed25519",
    "public_key_base64": "GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE="
  }]
}
JSON

# The container runs as an unprivileged user; mounted fixture files must be
# readable by it.
chmod 0755 "$generated" "$generated/tls"
chmod 0644 "$generated/config.json" "$generated/tls/cert.pem" "$generated/tls/key.pem"
# The ZAP image runs as its own unprivileged uid; the report directory must
# be writable by that uid on the host bind mount.
chmod 0777 "$out"
cp "$here/openapi.yaml" "$out/openapi.yaml"
cp "$here/zap-rules.conf" "$out/zap-rules.conf"

compose=(docker compose -f "$here/compose.yml")

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$repo_root"
# --exit-code-from zap makes the scan result the script result; ZAP exits
# non-zero when a FAIL-level rule fires.
"${compose[@]}" up --build --abort-on-container-exit --exit-code-from zap
