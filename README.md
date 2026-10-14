# NahaN Host Agent

## Automatic Core Host Reporting

The agent publishes its Ed25519 placement public key through its authenticated
heartbeat and issues 60-second, core-specific attestations over the root-only
Unix socket `/run/nahan-host-placement/placement.sock`. Updated native cores use
this socket automatically; the panel verifies the signature before assigning
their host. No TCP listener is opened and no enrollment credential is shared.
Existing conflicting placements are reported, not silently moved.

The signing key remains in the private agent state directory. For a root-running
containerized core, mount only `/run/nahan-host-placement` read-only at the same
path. Do not mount the agent state directory or enrollment keys. Mounting the
socket directory rather than its single file keeps socket replacement visible
after agent restart. A sandbox without socket access continues normal polling
but cannot report a verified host; it must not infer placement from public IP.
Non-root deployments require an explicitly permissioned socket integration.

Panel-connected Linux host agent for **server observability and scoped infrastructure management**. Independent
from the NahaN proxy core. Maintained by **NahaN** <nahancode@gmail.com>.

Version 0.4 adds signed automatic core placement to IPv4/IPv6 interface inventory, per-interface traffic counters,
uptime and managed IPv4 GRE links. Additional management capabilities are planned,
not implied by the project name. It is not a remote shell. Requires Linux,
iproute2, ping and systemd. No inbound
management port is opened. The agent polls the NahaN panel over verified HTTPS
using a separate, revocable host credential. This release uses bearer tokens,
not mutual TLS. Do not use HTTP or disable certificate verification.
Public HTTPS remains primary; direct IP fallback verifies the private NahaN CA
and fixed control identity. See [private control TLS](docs/private-control-tls.md)
for source installation, endpoint expansion, key custody and rotation limitations.

## Quick Interactive Install

Register the host in **Network Tunnels → Connect Server**, then choose **Copy and
Install**. Run this command on that host; it contains no enrollment secret:

```sh
(work="$(mktemp -d)" && trap 'rm -rf -- "$work"' EXIT && curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 https://raw.githubusercontent.com/NahaNCode/nahan-host-agent/a712641c408907e4099d27957e99c3e32fe7b16c/install.sh -o "$work/install.sh" && printf 'a4569a152b4b846ed63024bc0b5fec26dc5baa8694af651c01def2ae8322662e  %s\n' "$work/install.sh" | sha256sum --check --status && sudo bash "$work/install.sh")
```

The script is pinned to a reviewed commit and checksum, not mutable `main`.
Review [the installer](https://github.com/NahaNCode/nahan-host-agent/blob/a712641c408907e4099d27957e99c3e32fe7b16c/install.sh)
before granting root access. It supports Linux AMD64/ARM64 and running systemd.
On Debian/Ubuntu it offers to install missing dependencies after confirmation;
elsewhere install `curl`, `jq`, `iproute2`, `ping` and `coreutils` first.

1. Copy `config.json` in the panel and paste it at the configuration prompt.
2. Copy `agent.key` and paste it at the **hidden** key prompt. Never put it in
   the command, URL, shell history or public logs.
3. The installer verifies the pinned v0.4.0 binary checksum, then checks enrollment
   through public HTTPS or private-CA direct routes,
   reports the requested link count and asks before installing/starting the service.

The key is received from the panel once. Repeated copies are available only while
the package dialog remains open; closing destroys its in-memory copy. Downloading
first consumes the key too. Reissue if necessary; it revokes the previous key.
Clipboard contents are outside the panel's control: clear them after installation.
Do not use a shared machine or clipboard synchronization for the key.

For downloaded files, use `sudo bash install.sh --config ./config.json --key-file
./agent.key` after `chmod 600 agent.key`. The installer refuses a different
installed host identity or orphaned state. Existing state is never deleted.
Updating the same agent restarts its service, not unrelated GRE links.
`--check` verifies enrollment and the release without changing host settings:

```sh
sudo bash install.sh --check --config /etc/nahan-host-agent/config.json --key-file /etc/nahan-host-agent/agent.key
```

An active service is not proof of a successful tunnel. Wait for the panel heartbeat
and review each endpoint's probe result. Dependency installation may change system
packages; canceled enrollment otherwise leaves agent configuration unchanged.

## Manual Installation

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

[Release v0.3.0](https://github.com/NahaNCode/nahan-host-agent/releases/tag/v0.3.0)
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
