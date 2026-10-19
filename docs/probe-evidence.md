# Bounded Tunnel Probe Evidence

The host agent records TCP/ICMP attempt timestamps, duration, classified errors, cycle cancellation, boot ID, agent PID/start time and six interface counters. This is observation only; it never changes the GRE interface or decides routing authorization.

Selection:
- First baseline, changed outcome, and recovery.
- Identical healthy outcome: no more than once every five minutes per tunnel.
- Identical failure: no more than once per minute per tunnel.
- Hard limit of 12 records/minute across the agent. Extreme flapping may therefore be sampled, not exhaustively recorded.

Local storage is two rotated private JSONL files adjacent to `stateFile`, approximately 1 MiB each plus one bounded record. A record is at most 4096 bytes. Journal failures do not fail reconciliation; their warning is throttled to once per ten minutes. Selected reports are included in the ordinary authenticated heartbeat. Failed heartbeat delivery leaves local evidence; automatic replay of offline evidence is not implemented.

The backend validates bounded structured fields, stores sample IDs idempotently, keeps at most 2000 records per host and removes records older than seven days hourly. The nominal JSON payload ceiling is approximately 8 MiB per host, excluding DB indexes/replication/engine overhead. Owner host details expose the last 100 records. Legacy agents remain compatible but cannot supply retrospective detail.

No packet payloads, customer UUIDs, credentials, raw command errors or full configs are included. Kernel counters distinguish interface errors/drops from probe outcomes; they do not by themselves identify where a packet was lost.
