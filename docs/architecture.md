# Host-agent architecture

NahaN has separate resource identities: host (OS/network), core (proxy engine)
and tunnel (a managed link between two hosts). Host observability does not
replace core/service metering. Each has its own health and version.

## Current contract

An optional heartbeat telemetry object uses schemaVersion 1. It contains
collectedAt, bootId, uptimeSeconds and interfaces. Each interface includes
name, state, MTU, IPv4/IPv6 address/prefix/family/scope and RX/TX byte, packet,
error and dropped counters. Network discovery never rewrites enrollment
addresses, routes or existing tunnel endpoints.

The panel timestamps accepted reports itself, retains the last 240 samples
per host and the last 100 state-transition events. Polling is every 15 seconds.
This is a bounded recent monitoring window, not long-term accounting.
Counter rates require the same boot ID, a positive interval no longer than
60 seconds and monotonic counters. Never sum physical and tunnel bytes as
customer usage. Tunnel connectivity is a bound ICMP probe, not Internet quality.

The read-only observer and GRE reconciler are separate modules. New capabilities
must have typed, versioned desired-state contracts, explicit enrollment scopes,
bounded reports, ownership checks, tests and audit records. No arbitrary command
or unrestricted system-journal endpoint will be introduced.

## Roadmap

- Dedicated unprivileged observer and narrow privileged network worker.
- Explicit negotiated capabilities and granular per-host permissions.
- RTT, jitter and loss sampling with probe budgets and destination allowlists.
- CPU/memory/disk observations and independent agent/core health views.
- Redacted, scoped event streaming; SSE delivery and reconnect cursors.
- Time-series storage, retention policy, alerts and export.
- Per-tunnel outer-IP selection from verified inventory; immutable safe
  replacement rather than changing an active link in place.
- Infrastructure service-account metering, quotas and billing remain separate
  from host interface counters.

These are future capabilities, not features provided by version 0.2.
