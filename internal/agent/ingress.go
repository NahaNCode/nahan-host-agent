package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

// These policies own only their table and never flush the host firewall.
type IngressPolicy struct {
	ID      string   `json:"id"`
	Port    int      `json:"port"`
	Sources []string `json:"sources"`
}

func ingressRules(policies []IngressPolicy) (string, error) {
	if len(policies) > 64 {
		return "", errors.New("too many ingress policies")
	}
	ids, ports := map[string]bool{}, map[int]bool{}
	var b strings.Builder
	b.WriteString("table inet nahan_ingress {\n chain input { type filter hook input priority -10; policy accept;\n")
	for _, p := range policies {
		if !UUID(p.ID) || ids[p.ID] || ports[p.Port] || p.Port < 1024 || p.Port > 65535 || len(p.Sources) < 1 || len(p.Sources) > 32 {
			return "", errors.New("invalid ingress policy")
		}
		ids[p.ID], ports[p.Port] = true, true
		sources := append([]string(nil), p.Sources...)
		sort.Strings(sources)
		seen := map[string]bool{}
		for _, s := range sources {
			ip, e := netip.ParseAddr(s)
			if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.String() != s || seen[s] {
				return "", errors.New("invalid ingress source")
			}
			seen[s] = true
			fmt.Fprintf(&b, " ip saddr %s meta l4proto { tcp, udp } th dport %d accept\n", s, p.Port)
		}
		// Includes IPv6: an IPv4-only allowlist must not leave the IPv6 socket open.
		fmt.Fprintf(&b, " meta l4proto { tcp, udp } th dport %d drop\n", p.Port)
	}
	b.WriteString(" }\n}\n")
	return b.String(), nil
}

type inputRunner interface {
	RunInput(context.Context, string, []byte, ...string) ([]byte, error)
}

func (ExecRunner) RunInput(ctx context.Context, name string, input []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(input)
	return cmd.Output()
}

func (n Network) ApplyIngress(ctx context.Context, policies []IngressPolicy) error {
	rules, e := ingressRules(policies)
	if e != nil {
		return e
	}
	runner, ok := n.Runner.(inputRunner)
	if !ok {
		return errors.New("ingress runner unavailable")
	}
	// An atomic nft transaction leaves the previous rules intact on any failure.
	prefix := ""
	if _, e = n.Runner.Run(ctx, "nft", "list", "table", "inet", "nahan_ingress"); e == nil {
		prefix = "delete table inet nahan_ingress\n"
	}
	if _, e = runner.RunInput(ctx, "nft", []byte(prefix+rules), "-f", "-"); e != nil {
		return errors.New("ingress apply failed")
	}
	return nil
}
