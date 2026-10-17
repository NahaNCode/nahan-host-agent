package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const Version = "0.4.1"

type Config struct {
	PlacementSocket string   `json:"placementSocket,omitempty"`
	Panel           string   `json:"panel"`
	ID              string   `json:"id"`
	TokenFile       string   `json:"tokenFile"`
	StateFile       string   `json:"stateFile"`
	DirectIPs       []string `json:"directIPs,omitempty"`
}
type Manifest struct {
	Revision int64    `json:"revision"`
	Tunnels  []Tunnel `json:"tunnels"`
}
type Receipt struct {
	ID           string `json:"id"`
	Applied      bool   `json:"applied"`
	PeerAlive    bool   `json:"peerAlive"`
	Error        string `json:"error"`
	HealthMethod string `json:"healthMethod,omitempty"`
	HealthPort   int    `json:"healthPort,omitempty"`
}
type Report struct {
	PlacementKey string     `json:"placementKey,omitempty"`
	Version      string     `json:"version"`
	Revision     int64      `json:"revision"`
	Results      []Receipt  `json:"results"`
	Telemetry    *Telemetry `json:"telemetry,omitempty"`
}
type Client struct {
	Placement    *PlacementSigner
	Config       Config
	HTTP         *http.Client
	Network      Network
	State        Manifest
	directHTTP   []*http.Client
	preferred    int
	primaryRetry time.Time
}

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.Panel)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !UUID(c.ID) || !filepath.IsAbs(c.TokenFile) || !filepath.IsAbs(c.StateFile) {
		return nil, errors.New("invalid enrollment configuration")
	}
	clients, e := directClients(u, c.DirectIPs)
	if e != nil {
		return nil, e
	}
	return &Client{Config: c, HTTP: controlHTTP(nil), directHTTP: clients, Network: Network{ExecRunner{}}}, nil
}
func (c *Client) request(ctx context.Context, method, path string, body any, out any) error {
	token, e := os.ReadFile(c.Config.TokenFile)
	if e != nil {
		return errors.New("credential unavailable")
	}
	var b []byte
	if body != nil {
		b, e = json.Marshal(body)
		if e != nil {
			return e
		}
	}
	credential := strings.TrimSpace(string(token))
	if !validCredential(credential) {
		return errors.New("invalid credential")
	}
	clients := append([]*http.Client{c.HTTP}, c.directHTTP...)
	order := []int{0}
	if c.preferred > 0 && time.Now().Before(c.primaryRetry) {
		order = []int{c.preferred}
	}
	for i := 1; i < len(clients); i++ {
		if i != order[0] {
			order = append(order, i)
		}
	}
	for _, index := range order {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Config.Panel, "/")+"/core/v1/hosts/"+c.Config.ID+path, bytes.NewReader(b))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+credential)
		if index > 0 && req.URL.Hostname() == "pwaapi.nahanvpn.com" {
			req.Host = ControlServerName
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := clients[index].Do(req)
		if e != nil {
			clients[index].CloseIdleConnections()
			continue
		}
		if resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return errors.New("panel refused request")
		}
		data, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		resp.Body.Close()
		if e != nil {
			continue
		}
		if len(data) > 1<<20 {
			return errors.New("panel response too large")
		}
		if out != nil {
			if e = json.Unmarshal(data, out); e != nil {
				return errors.New("invalid panel response")
			}
		}
		c.preferred = index
		if index > 0 && !time.Now().Before(c.primaryRetry) {
			c.primaryRetry = time.Now().Add(time.Minute)
		}
		return nil
	}
	return errors.New("panel connection failed on all verified routes")
}

// Verify checks enrollment without loading state, reconciling or reporting.
func (c *Client) Verify(ctx context.Context) error {
	_, e := c.CheckEnrollment(ctx, 0)
	return e
}

// CheckEnrollment never reconciles interfaces. Route zero uses normal fallback;
// positive route numbers verify a specific configured private-CA endpoint.
func (c *Client) CheckEnrollment(ctx context.Context, route int) (Manifest, error) {
	var m Manifest
	if route < 0 || route > len(c.directHTTP) {
		return m, errors.New("invalid verification route")
	}
	if route > 0 {
		original := c.HTTP
		c.HTTP = c.directHTTP[route-1]
		originalDirect := c.directHTTP
		c.directHTTP = nil
		originalPreferred := c.preferred
		c.preferred = 0
		originalPanel := c.Config.Panel
		u, _ := url.Parse(c.Config.Panel)
		u.Host = ControlServerName + ":" + u.Port()
		if u.Port() == "" {
			u.Host = ControlServerName
		}
		c.Config.Panel = u.String()
		defer func() {
			c.HTTP = original
			c.Config.Panel = originalPanel
			c.directHTTP = originalDirect
			c.preferred = originalPreferred
		}()
	}
	e := c.request(ctx, "GET", "/manifest", nil, &m)
	return m, e
}
func (c *Client) Load() error {
	b, e := os.ReadFile(c.Config.StateFile)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	return json.Unmarshal(b, &c.State)
}
func (c *Client) save(m Manifest) error {
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	dir := filepath.Dir(c.Config.StateFile)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".state-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, c.Config.StateFile)
}
func sameTunnelTechnical(before, after Tunnel) bool {
	before.PeerTCPPorts = nil
	after.PeerTCPPorts = nil
	return reflect.DeepEqual(before, after)
}
func sameTunnelTopology(before, after []Tunnel) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		if !sameTunnelTechnical(before[i], after[i]) {
			return false
		}
	}
	return true
}
func (c *Client) Reconcile(ctx context.Context, m Manifest) (Report, error) {
	report := Report{Version: Version, Revision: m.Revision, Results: []Receipt{}}
	if m.Revision < c.State.Revision || len(m.Tunnels) > 32 {
		return report, errors.New("stale or oversized manifest")
	}
	if m.Revision == c.State.Revision && !sameTunnelTopology(m.Tunnels, c.State.Tunnels) {
		return report, errors.New("revision reused with different configuration")
	}
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, t := range m.Tunnels {
		if e := Validate(t); e != nil {
			return report, e
		}
		if ids[t.ID] || names[t.Name()] {
			return report, errors.New("duplicate tunnel")
		}
		ids[t.ID] = true
		names[t.Name()] = true
	}
	for _, old := range c.State.Tunnels {
		for _, t := range m.Tunnels {
			if old.ID == t.ID && !sameTunnelTechnical(old, t) {
				return report, errors.New("in-place technical mutation refused; remove then recreate")
			}
		}
	}
	// Persist the intent first so a restart can still account for partially created resources.
	union := Manifest{Revision: c.State.Revision, Tunnels: append([]Tunnel{}, m.Tunnels...)}
	for _, old := range c.State.Tunnels {
		if !ids[old.ID] {
			union.Tunnels = append(union.Tunnels, old)
		}
	}
	if e := c.save(union); e != nil {
		return report, e
	}
	for _, old := range c.State.Tunnels {
		if !ids[old.ID] {
			if e := c.Network.Remove(ctx, old); e != nil {
				return report, e
			}
		}
	}
	all := true
	for _, t := range m.Tunnels {
		r := Receipt{ID: t.ID}
		e := c.Network.Apply(ctx, t)
		if e != nil {
			all = false
			r.Error = e.Error()
		} else {
			r.Applied = true
			r.PeerAlive, r.HealthMethod, r.HealthPort = c.Network.ProbeWithEvidence(ctx, t)
		}
		report.Results = append(report.Results, r)
	}
	if all {
		if e := c.save(m); e != nil {
			return report, e
		}
		c.State = Manifest{Revision: m.Revision, Tunnels: append([]Tunnel{}, m.Tunnels...)}
	} else {
		c.State = union
	}
	return report, nil
}
func (c *Client) Tick(ctx context.Context) error {
	var m Manifest
	if e := c.request(ctx, "GET", "/manifest", nil, &m); e != nil {
		return e
	}
	r, e := c.Reconcile(ctx, m)
	if e != nil {
		return e
	}
	// An unavailable inventory must not interrupt GRE reconciliation or heartbeats.
	r.Telemetry, _ = c.Network.Inventory(ctx)
	if c.Placement != nil {
		r.PlacementKey = c.Placement.PublicKey()
	}
	return c.request(ctx, "POST", "/heartbeat", r, nil)
}
