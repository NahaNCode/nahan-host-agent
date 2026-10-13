# Control protocol v1

Enrollment configuration contains `panel` (HTTPS API root, ending in `/api`),
host `id`, absolute `tokenFile` and absolute `stateFile`. No secret is embedded
in configuration JSON. Host IDs and credentials are distinct from core IDs.

Every 15 seconds the agent uses `Authorization: Bearer <host credential>`:

- `GET /api/core/v1/hosts/{id}/manifest`
- `POST /api/core/v1/hosts/{id}/heartbeat`

Manifest: `revision` and `tunnels`. A tunnel contains UUID `id`, outer IPv4
`local`/`remote`, private IPv4 CIDR `inner` (/30), `peer`, nonzero uint32 `key`,
`mtu` (1280–1472) and `ttl` (1–255). Each host receives its side of the link.

An absent previously-managed tunnel requests removal of that owned interface.
A stale manifest or in-place technical mutation is refused. Heartbeat includes
`version`, `revision`, and a result per desired link with `id`, `applied`,
`peerAlive`, and a sanitized operation `error`. Peer reachability is not an
apply acknowledgment; a link can be locally applied and have a failing peer.

Version 0.2 additionally sends optional telemetry schemaVersion 1; see
[architecture](architecture.md). Older agents may omit it and still reconcile
GRE. Deploy the compatible panel before upgrading agents.

The panel must treat reports older than one minute as stale, never healthy.
Revoking a credential prevents new control requests but does not erase local
network resources. This version does not accept arbitrary host commands,
firewall changes, shell scripts, SSH passwords, or proxy credentials.
