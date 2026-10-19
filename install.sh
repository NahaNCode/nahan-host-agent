#!/usr/bin/env bash
set -euo pipefail
umask 077

VERSION=0.4.1
ROOT=https://github.com/NahaNCode/nahan-host-agent/releases/download/v$VERSION
check=false
config_path=
key_path=
binary_path=
while (($#)); do
  case "$1" in
    --check) check=true; shift ;;
    --config) config_path="${2:?Missing config path}"; shift 2 ;;
    --key-file) key_path="${2:?Missing key path}"; shift 2 ;;
    --binary) binary_path="${2:?Missing local binary path}"; shift 2 ;;
    --help) printf 'NahaN installer: [--check] [--config FILE] [--key-file FILE] [--binary LOCALLY_BUILT_FILE]\n'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done
fail() { printf 'Error: %s\n' "$1" >&2; exit 1; }
[[ $(uname -s) == Linux ]] || fail 'Linux is required.'
$check || [[ $EUID == 0 ]] || fail 'Run the installer with sudo.'
case "$(uname -m)" in
  x86_64) arch=amd64; hash=de9bb5e3ab8693581eb09adc03b25fd39ecd562d780027f0318976a53b7e8666 ;;
  aarch64|arm64) arch=arm64; hash=5ebc0c1543159349ce8da91c1a4f78842d29d78e41690020bf9998e4c7fede12 ;;
  *) fail 'Supported architectures: AMD64 and ARM64.' ;;
esac
work=$(mktemp -d)
trap 'unset token; rm -rf -- "$work"' EXIT
trap 'exit 130' INT TERM
printf '\nNahaN Host Agent %s\n' "$VERSION"
missing=()
for pair in curl:curl jq:jq ip:iproute2 ping:iputils-ping sha256sum:coreutils; do
  command -v "${pair%%:*}" >/dev/null || missing+=("${pair#*:}")
done
if (("${#missing[@]}")); then
  $check && fail 'Missing dependencies; install curl jq iproute2 iputils-ping coreutils.'
  command -v apt-get >/dev/null || fail 'Install curl jq iproute2 iputils-ping coreutils with your package manager.'
  printf 'Install missing packages: %s? [y/N] ' "${missing[*]}" > /dev/tty
  read -r answer < /dev/tty
  [[ $answer == y || $answer == Y ]] || fail 'Dependencies were not installed.'
  apt-get update -qq
  apt-get install -y --no-install-recommends "${missing[@]}"
fi
if [[ -n $config_path ]]; then
  [[ -f $config_path ]] || fail 'Config file not found.'
  cp -- "$config_path" "$work/config.json"
else
  printf '\n1/3 Paste config.json on one line (or enter its file path):\n' > /dev/tty
  IFS= read -r config < /dev/tty
  if [[ -f $config ]]; then cp -- "$config" "$work/config.json"
  else printf '%s\n' "$config" > "$work/config.json"; fi
  unset config
fi
jq -e '
  type=="object" and (.panel|type=="string") and
  (.panel|test("^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~-]+)*$")) and
  (.id|type=="string") and (.id|test("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")) and
  .tokenFile=="/etc/nahan-host-agent/agent.key" and
  .stateFile=="/var/lib/nahan-host-agent/state.json"
' "$work/config.json" >/dev/null 2>&1 || fail 'Invalid enrollment config; paste the config issued by NahaN.'
panel=$(jq -r .panel "$work/config.json")
id=$(jq -r .id "$work/config.json")
printf 'Panel: %s\nHost ID: %s\n' "$panel" "$id"
if ! $check && [[ -f /var/lib/nahan-host-agent/state.json && ! -f /etc/nahan-host-agent/config.json ]]; then
  fail 'Existing state has no installed identity; refusing to adopt it.'
fi
if ! $check && [[ -f /etc/nahan-host-agent/config.json ]]; then
  old_id=$(jq -er .id /etc/nahan-host-agent/config.json)
  old_panel=$(jq -er .panel /etc/nahan-host-agent/config.json)
  [[ $old_id == "$id" && $old_panel == "$panel" ]] || fail 'Another host identity is installed; replacement refused. Existing state is untouched.'
fi
if [[ -n $key_path ]]; then
  [[ -f $key_path ]] || fail 'Key file not found.'
  mode=$(stat -c %a "$key_path")
  (( (8#$mode & 077) == 0 )) || fail 'Key file must not be accessible by group or others; use chmod 600.'
  token=$(<"$key_path")
else
  printf '\n2/3 Paste agent.key (hidden): ' > /dev/tty
  IFS= read -rs token < /dev/tty
  printf '\n' > /dev/tty
fi
[[ $token =~ ^[A-Za-z0-9_-]{32,256}$ ]] || fail 'Invalid host key.'
printf '%s\n' "$token" > "$work/agent.key"
printf 'Authorization: Bearer %s\n' "$token" > "$work/headers"
unset token
if [[ -n $binary_path ]]; then
  [[ -f $binary_path && -x $binary_path ]] || fail 'Locally built executable not found.'
  printf 'Using explicitly supplied locally built executable. Trust its reviewed source.\n'
  cp -- "$binary_path" "$work/agent"
else
  printf 'Downloading verified %s release…\n' "$arch"
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 180 \
  "$ROOT/nahan-host-agent-linux-$arch" -o "$work/agent"
printf '%s  %s\n' "$hash" "$work/agent" | sha256sum --check --status ||
  fail 'Release checksum mismatch; installation refused.'
fi
chmod 0700 "$work/agent"
jq --arg token "$work/agent.key" --arg state "$work/state.json" '.tokenFile=$token | .stateFile=$state' "$work/config.json" > "$work/check.json"
printf 'Checking enrollment: public HTTPS, then verified private-CA IP routes…\n'
"$work/agent" --config "$work/check.json" --check-enrollment > "$work/check-result.json" ||
  fail 'Panel enrollment could not be verified. No installation changes were made.'
jq -e '(.revision|type=="number") and (.managedLinks|type=="number")' "$work/check-result.json" >/dev/null || fail 'Unexpected enrollment check response.'
count=$(jq '.managedLinks' "$work/check-result.json")
if $check; then printf 'CHECK PASSED: enrollment and executable verified; no host settings changed.\n'; exit 0; fi
[[ -d /run/systemd/system ]] || fail 'A running systemd host is required.'
printf '\n3/3 Install/start this agent? %s managed link(s) are requested by the panel.\n' "$count" > /dev/tty
printf 'Only NahaN-owned GRE interfaces may be reconciled. Existing GREs/default routes are protected. [y/N] ' > /dev/tty
read -r answer < /dev/tty
[[ $answer == y || $answer == Y ]] || fail 'Cancelled; no agent files or service settings were changed.'
install -d -m 0700 /etc/nahan-host-agent /var/lib/nahan-host-agent
install -m 0600 "$work/config.json" /etc/nahan-host-agent/config.json.next
install -m 0600 "$work/agent.key" /etc/nahan-host-agent/agent.key.next
install -m 0755 "$work/agent" /usr/local/bin/nahan-host-agent.next
mv /etc/nahan-host-agent/config.json.next /etc/nahan-host-agent/config.json
mv /etc/nahan-host-agent/agent.key.next /etc/nahan-host-agent/agent.key
mv /usr/local/bin/nahan-host-agent.next /usr/local/bin/nahan-host-agent
printf '%s\n' '[Unit]' 'Description=NahaN Host Agent' 'After=network-online.target' 'Wants=network-online.target' \
  '' '[Service]' 'ExecStart=/usr/local/bin/nahan-host-agent --config /etc/nahan-host-agent/config.json' \
  'Restart=on-failure' 'RestartSec=10' 'User=root' 'UMask=0077' 'NoNewPrivileges=yes' \
  'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW' 'ProtectSystem=strict' 'ProtectHome=yes' \
  'PrivateTmp=yes' 'ReadWritePaths=/var/lib/nahan-host-agent /proc/sys/net/ipv4/conf /run' 'ReadOnlyPaths=/proc/sys /sys' \
  'RuntimeDirectory=nahan-host-placement' 'RuntimeDirectoryMode=0700' 'RuntimeDirectoryPreserve=yes' \
  'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK' 'ProtectKernelTunables=no' \
  'ProtectKernelModules=yes' 'ProtectControlGroups=yes' 'LockPersonality=yes' \
  'MemoryDenyWriteExecute=yes' '' '[Install]' 'WantedBy=multi-user.target' > "$work/unit"
install -m 0644 "$work/unit" /etc/systemd/system/nahan-host-agent.service
systemctl daemon-reload
systemctl enable nahan-host-agent >/dev/null
systemctl restart nahan-host-agent
systemctl is-active --quiet nahan-host-agent || fail 'Installed but service did not become active; inspect journalctl -u nahan-host-agent.'
printf '\nConnected enrollment verified; agent is active. Panel heartbeat should appear shortly.\n'
printf 'Status: systemctl status nahan-host-agent\nLogs: journalctl -u nahan-host-agent -n 20\n'
