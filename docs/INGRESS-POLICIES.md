# Panel-Managed SS Access

Agent 0.5.0 reports `ingressRuntimeVersion: 1`. The authenticated host manifest
may contain `ingressPolicies`, each with a UUID, a high port and 1-32 exact IPv4
source addresses. The backend ties policies to enabled infrastructure SS inputs
on a freshly verified core/host placement. It does not accept arbitrary ports.

The agent validates the complete manifest before changing networking. A single
atomic nftables transaction replaces only the reserved `inet nahan_ingress`
table. Existing firewall tables, default routes and SSH rules are untouched.
Disallowed TCP/UDP packets for the managed port are dropped, including IPv6.
An allow rule does not bypass stricter rules in another host firewall table.

Desired state is saved with mode 0600 before reconciliation. Startup restores
persisted ingress restrictions before starting placement reporting or polling.
A failed transaction does not acknowledge the host revision. The panel shows
pending state until the exact manifest revision is applied.

Prerequisite: `nft` and CAP_NET_ADMIN. Hosts without this capability must not
receive an access policy. Deployment must order SS listener startup after local
policy restoration; otherwise a reboot could briefly expose a listener.
`--restore-ingress` performs only local restoration and exits, without contacting
the panel or reconciling GRE. Deploy `nahan-ingress-restore.service` and add both
`Requires=nahan-ingress-restore.service` and `After=nahan-ingress-restore.service`
to units hosting managed SS listeners. The restore unit remains active so normal
core restarts do not replay old state concurrently with the running agent.
Manual restrictions must remain until panel-policy acknowledgement and must be
removed only from their dedicated owned chains, never with a global flush.
