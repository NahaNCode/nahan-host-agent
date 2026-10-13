package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

type Tunnel struct {
	ID     string `json:"id"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Inner  string `json:"inner"`
	Peer   string `json:"peer"`
	Key    uint32 `json:"key"`
	MTU    int    `json:"mtu"`
	TTL    int    `json:"ttl"`
}
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type Network struct{ Runner Runner }
type Link struct {
	Name  string `json:"ifname"`
	Alias string `json:"ifalias"`
	Info  struct {
		Kind string `json:"info_kind"`
		Data struct {
			Local  string          `json:"local"`
			Remote string          `json:"remote"`
			TTL    int             `json:"ttl"`
			IKey   json.RawMessage `json:"ikey"`
			OKey   json.RawMessage `json:"okey"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func keyValue(raw json.RawMessage) uint32 {
	var value uint32
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0
	}
	if v, e := strconv.ParseUint(s, 10, 32); e == nil {
		return uint32(v)
	}
	if a, e := netip.ParseAddr(s); e == nil && a.Is4() {
		b := a.As4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	return 0
}
func (n Network) verify(ctx context.Context, t Tunnel) error {
	links, e := n.links(ctx)
	if e != nil {
		return e
	}
	for _, l := range links {
		if l.Name == t.Name() {
			d := l.Info.Data
			if d.Local != t.Local || d.Remote != t.Remote || d.TTL != t.TTL || keyValue(d.IKey) != t.Key || keyValue(d.OKey) != t.Key {
				return errors.New("managed GRE configuration drift; refusing replacement")
			}
			return nil
		}
	}
	return errors.New("managed GRE disappeared")
}

func (t Tunnel) Name() string { return "nhg" + strings.ReplaceAll(t.ID, "-", "")[:12] }
func UUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func Validate(t Tunnel) error {
	if !UUID(t.ID) || t.Key == 0 || t.MTU < 1280 || t.MTU > 1472 || t.TTL < 1 || t.TTL > 255 {
		return errors.New("invalid GRE identity or options")
	}
	a, err := netip.ParseAddr(t.Local)
	if err != nil || !a.Is4() || !a.IsGlobalUnicast() {
		return errors.New("invalid outer local address")
	}
	b, err := netip.ParseAddr(t.Remote)
	if err != nil || !b.Is4() || !b.IsGlobalUnicast() || a == b {
		return errors.New("invalid outer remote address")
	}
	p, err := netip.ParsePrefix(t.Inner)
	if err != nil || !p.Addr().Is4() || p.Bits() != 30 || !p.Addr().IsPrivate() {
		return errors.New("inner must be private IPv4 /30")
	}
	peer, err := netip.ParseAddr(t.Peer)
	if err != nil || !p.Contains(peer) || peer == p.Addr() {
		return errors.New("invalid inner peer")
	}
	base := p.Masked().Addr().As4()
	host := p.Addr().As4()
	other := peer.As4()
	if host[3] == base[3] || host[3] == base[3]+3 || other[3] == base[3] || other[3] == base[3]+3 {
		return errors.New("network and broadcast addresses forbidden")
	}
	return nil
}
func (n Network) links(ctx context.Context) ([]Link, error) {
	b, e := n.Runner.Run(ctx, "ip", "-j", "-d", "link", "show")
	if e != nil {
		return nil, e
	}
	var out []Link
	e = json.Unmarshal(b, &out)
	return out, e
}
func (n Network) owned(ctx context.Context, t Tunnel) (bool, error) {
	links, e := n.links(ctx)
	if e != nil {
		return false, e
	}
	for _, l := range links {
		if l.Name == t.Name() {
			if l.Alias != "nahan:"+t.ID || l.Info.Kind != "gre" {
				return false, errors.New("interface exists without matching ownership")
			}
			return true, nil
		}
	}
	return false, nil
}
func (n Network) conflict(ctx context.Context, t Tunnel) error {
	data, e := n.Runner.Run(ctx, "ip", "-j", "-4", "route", "show", "table", "all")
	if e != nil {
		return e
	}
	var routes []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if e = json.Unmarshal(data, &routes); e != nil {
		return e
	}
	inner, _ := netip.ParsePrefix(t.Inner)
	for _, r := range routes {
		if r.Dev == t.Name() || r.Dst == "default" {
			continue
		}
		p, e := netip.ParsePrefix(r.Dst)
		if e != nil {
			a, e := netip.ParseAddr(r.Dst)
			if e != nil {
				continue
			}
			p = netip.PrefixFrom(a, 32)
		}
		if p.Contains(inner.Addr()) || inner.Contains(p.Addr()) {
			return errors.New("inner network overlaps an existing route")
		}
	}
	data, e = n.Runner.Run(ctx, "ip", "-j", "-4", "address", "show")
	if e != nil {
		return e
	}
	var addresses []struct {
		Name string `json:"ifname"`
		Addr []struct {
			Local string `json:"local"`
		} `json:"addr_info"`
	}
	if e = json.Unmarshal(data, &addresses); e != nil {
		return e
	}
	localFound := false
	for _, l := range addresses {
		for _, a := range l.Addr {
			if a.Local == t.Local {
				localFound = true
			}
		}
	}
	if !localFound {
		return errors.New("outer local address is not assigned to this host")
	}
	return nil
}
func (n Network) Apply(ctx context.Context, t Tunnel) error {
	if e := Validate(t); e != nil {
		return e
	}
	exists, e := n.owned(ctx, t)
	if e != nil {
		return e
	}
	if exists {
		return n.verify(ctx, t)
	}
	if e = n.conflict(ctx, t); e != nil {
		return e
	}
	args := []string{"tunnel", "add", t.Name(), "mode", "gre", "local", t.Local, "remote", t.Remote, "key", fmt.Sprint(t.Key), "ttl", fmt.Sprint(t.TTL)}
	if _, e = n.Runner.Run(ctx, "ip", args...); e != nil {
		return errors.New("GRE creation failed")
	}
	// Roll back only the interface created by this operation, never pre-existing links.
	fail := func() error {
		_, _ = n.Runner.Run(ctx, "ip", "link", "del", "dev", t.Name())
		return errors.New("GRE setup failed; created interface rollback attempted")
	}
	for _, args := range [][]string{{"link", "set", "dev", t.Name(), "alias", "nahan:" + t.ID}, {"address", "add", t.Inner, "dev", t.Name()}, {"link", "set", "dev", t.Name(), "mtu", fmt.Sprint(t.MTU), "up"}} {
		if _, e = n.Runner.Run(ctx, "ip", args...); e != nil {
			return fail()
		}
	}
	return nil
}
func (n Network) Remove(ctx context.Context, t Tunnel) error {
	if e := Validate(t); e != nil {
		return e
	}
	exists, e := n.owned(ctx, t)
	if e != nil || !exists {
		return e
	}
	_, e = n.Runner.Run(ctx, "ip", "link", "del", "dev", t.Name())
	return e
}
func (n Network) Probe(ctx context.Context, t Tunnel) bool {
	if Validate(t) != nil {
		return false
	}
	_, e := n.Runner.Run(ctx, "ping", "-n", "-c", "2", "-W", "2", "-I", t.Name(), t.Peer)
	return e == nil
}
