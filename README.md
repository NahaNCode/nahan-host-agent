# NahaN Host Agent

Panel-connected Linux host agent for **server observability and scoped infrastructure management**. Independent
from the NahaN proxy core. Maintained by **NahaN** <nahancode@gmail.com>.

Version 0.2 provides IPv4/IPv6 interface inventory, per-interface traffic counters,
uptime and managed IPv4 GRE links. Additional management capabilities are planned,
not implied by the project name. It is not a remote shell. Requires Linux,
iproute2, ping and systemd. No inbound
management port is opened. The agent polls the NahaN panel over verified HTTPS
using a separate, revocable host credential. This release uses bearer tokens,
not mutual TLS. Do not use HTTP or disable certificate verification.

## Connect to NahaN

1. In **Network Tunnels → Connect Server**, register the server's assigned IPv4.
2. Download `config.json` and the one-time `agent.key` within ten minutes.
   Downloads are OWNER-authenticated. Pending packages expire on panel restart.
   Use **Reissue Package** if needed; the old credential then becomes invalid.
   Neither file is a proxy-core configuration. Do not reuse a core key or panel
   login password.
3. Build and install from a reviewed checkout:

```sh
go test -race ./...
go build -trimpath -o nahan-host-agent ./cmd/nahan-host-agent
sudo install -d -m 0700 /etc/nahan-host-agent /var/lib/nahan-host-agent
sudo install -m 0600 config.json agent.key /etc/nahan-host-agent/
sudo install -m 0755 nahan-host-agent /usr/local/bin/nahan-host-agent
sudo install -m 0644 deploy/nahan-host-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nahan-host-agent
sudo systemctl status nahan-host-agent
```

The initial installation requires host administrative access. The unit has
`CAP_NET_ADMIN` and `CAP_NET_RAW`, a read-only filesystem except its state
directory, and no arbitrary command endpoint. These capabilities are powerful:
the application validates every operation. See [security](SECURITY.md).

## Prebuilt binaries

[Release v0.1.0](https://github.com/NahaNCode/nahan-host-agent/releases/tag/v0.1.0)
contains static Linux AMD64 and ARM64 builds and `SHA256SUMS`. Choose the host's
architecture and verify the downloaded binary's checksum before installing.
This is an initial pre-release, not general server-management readiness.

## Manage a link

Register both hosts, select them in the panel, and choose two unused private
host addresses in the same /30. Save disabled, review, then apply explicitly.
The panel allocates a nonzero GRE key so a managed link can coexist with a
previous unkeyed link between the same hosts. GRE keys identify links; they do
not encrypt traffic or authenticate peers.

Agent operations never change the default route, forwarding sysctls, firewall,
NAT, proxy configuration or unrelated interfaces. Your provider and firewall
must already permit GRE (IP protocol 47). A successful peer probe confirms
inner ICMP reachability, **not SS authentication or Internet egress**.

The interface name is derived from the tunnel UUID and marked with an ownership
alias. Existing names without matching ownership are refused. Overlapping
local routes are refused. Technical parameters are immutable in this release:
create a replacement link, verify it, then retire the old link deliberately.

Disable a link in the panel and wait for both agents to acknowledge removal
before deleting its record. Stopping or revoking an agent does not silently
delete its interfaces. State is retained across restarts. Do not delete state
files during active operations.

## Documentation

- [راهنمای فارسی](docs/README.fa.md)
- [Control protocol](docs/protocol.md)
- [Security and limitations](SECURITY.md)
- [Architecture and roadmap](docs/architecture.md)

## License

GPL-3.0-only. Copyright (c) 2026 NahaN. The Go standard library and external
operating-system utilities retain their own licenses.
