# Private Control TLS

Version 0.3 keeps public HTTPS as the primary route. For the NahaN panel, network
failures and HTTP 502/503/504 can fall back to two direct Ocean addresses. Direct
connections trust **only** the embedded NahaN Control Root and verify
`control.nahan.internal`. IPs are routing coordinates, not trusted identities.
No public DNS or public CA is needed on direct routes. TLS remains mandatory;
`InsecureSkipVerify`, TOFU and unauthenticated HTTP are not used.

## Enrollment and Source Builds

The root certificate is public. It is embedded in the reviewed source and release
binary; its private key is never distributed. Each installation still needs an
OWNER-issued host ID and a separate revocable `agent.key`. Possessing public
source or a root certificate grants no host or panel privileges.

Existing enrollment configurations work without changes. For the official panel,
the default endpoint set (version 1) is `152.53.172.146`, `152.53.176.197`, port 443.
Optional `directIPs` in the OWNER-issued configuration replaces that list, up to
eight distinct public IPs. An empty list disables fallback. Other panel hostnames
do not inherit NahaN endpoints or private trust. Configuration is trusted operator
input, not an unsigned list discovered from the network. Adding an IP requires
deploying a valid control certificate and the restricted API service on it first.
Updates for existing agents must be delivered through authenticated operator
configuration; automatic endpoint discovery is not implemented.

Build from a reviewed checkout using Go 1.24 or newer:

```sh
go test -race ./...
CGO_ENABLED=0 go build -buildvcs=false -trimpath -o nahan-host-agent ./cmd/nahan-host-agent
chmod 600 agent.key
sudo bash install.sh --binary ./nahan-host-agent --config ./config.json --key-file ./agent.key
```

`--binary` explicitly trusts your local build, instead of a prebuilt release hash.
The installer checks enrollment using that executable before changing service
files; it does not require the public HTTPS route to succeed. Downloads of the
installer/binary still require an accessible GitHub path; use a reviewed local
checkout when that bootstrap path is unavailable.

## Connection Behavior

Public HTTPS is attempted first. A working direct route is preferred for up to
one minute, then public HTTPS is probed again. Every request has fresh bounded
HTTP/1.1 transport: no stuck shared HTTP/2 session, no redirects and no implicit
environment proxy. Each route has a 12-second ceiling. HTTP authorization errors,
invalid JSON, oversized responses and revision conflicts are terminal.

Only manifest reads and idempotent host reports are retried. A timeout may happen
after a report was recorded, so telemetry can contain a duplicate sample. This
is not an exactly-once command channel; arbitrary writes must not reuse this
transport without explicit idempotency design.

Check without touching state or interfaces:

```sh
nahan-host-agent --config /etc/nahan-host-agent/config.json --check-enrollment
nahan-host-agent --config /etc/nahan-host-agent/config.json --check-enrollment --check-route 1
nahan-host-agent --config /etc/nahan-host-agent/config.json --check-enrollment --check-route 2
```

A check authenticates and reads the manifest, not heartbeat success or GRE health.

## Operator PKI Lifecycle

The encrypted root and encrypted name-constrained issuing key are held separately
from production endpoints. The issuing certificate permits only the control DNS
identity. Production holds a unique leaf key and public certificate chain per
endpoint, not CA signing keys. Initial leaves expire after 90 days; renew and
reload them before expiry. Monitor certificate expiry operationally.

Back up encrypted CA keys and their passphrase in separately controlled offline
storage. Local encryption is not a substitute for offline custody. Do not put
private keys, passphrases or host credentials in git, CI artifacts or logs.

For planned root rotation: release trust for old and new roots first, roll out
agents, rotate endpoint chains, then remove the old root in a later release.
For leaf compromise: remove the affected endpoint, rotate its key/certificate
and revoke exposed host credentials. This version does not implement online
CRL/OCSP checks: an old leaf can remain trusted until expiry unless the issuer
trust is replaced in agent releases. Treat that limitation as part of incident
response, not as automatic revocation. Issuer/root compromise requires an urgent
trust-store update; changing only the IP is insufficient.

## Endpoint Exposure

Both endpoints use existing 443 listeners and a separate SNI virtual host.
Only `/api/core/v1/hosts/<uuid>/manifest` and `/heartbeat` are exposed; backend host
authentication remains authoritative. Admin endpoints and arbitrary URL proxying
are not available. No new firewall exception or canceled control relay is needed.
The two addresses are on one machine, so they do not provide host-level HA.

Templates: `deploy/private-control/nginx.conf`, `apache.conf`. The Apache/LiteSpeed
include must survive panel-managed config regeneration; verify it after updates.
Rollback removes only the new control virtual hosts and restores the previous
agent binary. Do not change GRE interfaces, routes, public certificates or keys.
