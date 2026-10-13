# Security model

The panel has OWNER-only management endpoints. Each host receives its own
random bearer credential; the panel stores only its SHA-256 digest. HTTPS
certificate verification is mandatory and redirects are rejected. Credentials
must be root-owned mode 0600 and must never enter Git, screenshots or logs.

The root-run systemd unit restricts capabilities to NET_ADMIN and NET_RAW and
writable paths to its private state directory. NET_ADMIN is not restricted by
Linux to a particular interface: ownership checks in the agent are an important
application boundary, not a kernel-enforced sandbox. Do not grant arbitrary
shell execution. A future split privileged worker and mTLS enrollment are
planned hardening, not features of this version.

The manifest is versioned and limited to 32 links. IDs, addresses, subnets,
keys, MTU and TTL are validated before any command. Commands use fixed argument
arrays, never a shell. Unknown interfaces cannot be adopted or removed. Only
managed interfaces have automatic connected routes added by IP address setup.
Unrelated routes and interfaces are never explicitly changed.

Two-host creation is not a distributed atomic transaction. One side may remain
pending or fail independently. The panel must expose both receipts; operators
can disable the link to request cleanup. The agent rolls back its newly-created
interface if local address/MTU setup fails. A crash between interface creation
and setting its alias can leave an unowned orphan; fail-closed behavior requires
manual inspection rather than deleting an unknown interface.

GRE has no encryption or cryptographic authentication. Nonzero GRE keys avoid
link ambiguity but are not passwords. No SS credentials or proxy services are
managed here. SS endpoint tests are separate from inner GRE probes.

Report vulnerabilities privately to nahancode@gmail.com, without live keys.
