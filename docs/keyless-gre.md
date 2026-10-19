# Keyless GRE Profile

Agent 0.5.0 accepts key zero as an unkeyed GRE interface: it omits the `key`
argument entirely. The panel creates this profile with MTU 1400 and TTL 255.
Legacy nonzero keys continue to work; an existing interface is never silently
replaced when its outer endpoints, key or TTL change.

For unkeyed managed interfaces the agent reconciles `all.rp_filter=0` and the
interface's `rp_filter=0`, plus one idempotent INPUT GRE ACCEPT rule scoped to
both outer endpoints and tagged with the tunnel UUID. Removal deletes only that
rule and the owned interface. It does not restore global reverse-path filtering,
since another active GRE may still need it. This host-wide policy relaxation is
intentional and matches the deployed document-based profile.

The systemd service permits writes only to the IPv4 interface sysctl subtree
within the otherwise read-only kernel settings. `/run` is writable for the
system-wide iptables lock. Kernel-module and control-group protection remain on.
No NAT, forwarding, default-route or customer-core modification is performed.

The panel's optional `tunnel_address` is separate from the host's primary
address. Inbound/customer addresses are not changed when an operator migrates
the GRE transport to a secondary address. The address must actually exist on
the host; normal conflict checks still enforce that requirement.

Keyless GRE permits one tuple for a given local/remote outer pair. An existing
unmanaged keyless GRE with that tuple must not be removed or adopted silently.
Technical changes to live tunnels require a staged operator migration with
rollback, followed by matching persisted agent state and panel revision.
