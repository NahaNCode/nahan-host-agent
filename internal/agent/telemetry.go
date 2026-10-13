package agent

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Address struct {
	Address string `json:"address"`
	Prefix  int    `json:"prefix"`
	Family  string `json:"family"`
	Scope   string `json:"scope"`
}
type Counters struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Errors  uint64 `json:"errors"`
	Dropped uint64 `json:"dropped"`
}
type Interface struct {
	Name      string    `json:"name"`
	State     string    `json:"state"`
	MTU       int       `json:"mtu"`
	Addresses []Address `json:"addresses"`
	RX        Counters  `json:"rx"`
	TX        Counters  `json:"tx"`
}
type Telemetry struct {
	SchemaVersion int         `json:"schemaVersion"`
	CollectedAt   string      `json:"collectedAt"`
	BootID        string      `json:"bootId"`
	UptimeSeconds float64     `json:"uptimeSeconds"`
	Interfaces    []Interface `json:"interfaces"`
}

// Inventory is read-only. No routes, credentials, process arguments or system logs are collected.
func (n Network) Inventory(ctx context.Context) (*Telemetry, error) {
	raw, err := n.Runner.Run(ctx, "ip", "-j", "-s", "address", "show")
	if err != nil {
		return nil, err
	}
	var links []struct {
		Name      string `json:"ifname"`
		State     string `json:"operstate"`
		MTU       int    `json:"mtu"`
		Addresses []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
			Family string `json:"family"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
		Stats struct {
			RX Counters `json:"rx"`
			TX Counters `json:"tx"`
		} `json:"stats64"`
	}
	if err = json.Unmarshal(raw, &links); err != nil {
		return nil, err
	}
	out := &Telemetry{SchemaVersion: 1, CollectedAt: time.Now().UTC().Format(time.RFC3339), Interfaces: []Interface{}}
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	out.BootID = strings.TrimSpace(string(boot))
	uptime, _ := os.ReadFile("/proc/uptime")
	if parts := strings.Fields(string(uptime)); len(parts) > 0 {
		out.UptimeSeconds, _ = strconv.ParseFloat(parts[0], 64)
	}
	for _, link := range links {
		if len(out.Interfaces) >= 128 {
			break
		}
		entry := Interface{Name: link.Name, State: link.State, MTU: link.MTU, Addresses: []Address{}, RX: link.Stats.RX, TX: link.Stats.TX}
		for _, a := range link.Addresses {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if len(entry.Addresses) >= 32 {
				break
			}
			entry.Addresses = append(entry.Addresses, Address{Address: ip.String(), Prefix: a.Prefix, Family: a.Family, Scope: a.Scope})
		}
		out.Interfaces = append(out.Interfaces, entry)
	}
	return out, nil
}
