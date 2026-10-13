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

const Version = "0.1.0"

type Config struct {
	Panel     string `json:"panel"`
	ID        string `json:"id"`
	TokenFile string `json:"tokenFile"`
	StateFile string `json:"stateFile"`
}
type Manifest struct {
	Revision int64    `json:"revision"`
	Tunnels  []Tunnel `json:"tunnels"`
}
type Receipt struct {
	ID        string `json:"id"`
	Applied   bool   `json:"applied"`
	PeerAlive bool   `json:"peerAlive"`
	Error     string `json:"error"`
}
type Report struct {
	Version  string    `json:"version"`
	Revision int64     `json:"revision"`
	Results  []Receipt `json:"results"`
}
type Client struct {
	Config  Config
	HTTP    *http.Client
	Network Network
	State   Manifest
}

func New(c Config) (*Client, error) {
	u, e := url.Parse(c.Panel)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !UUID(c.ID) || !filepath.IsAbs(c.TokenFile) || !filepath.IsAbs(c.StateFile) {
		return nil, errors.New("invalid enrollment configuration")
	}
	return &Client{Config: c, HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}, Network: Network{ExecRunner{}}}, nil
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
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Config.Panel, "/")+"/core/v1/hosts/"+c.Config.ID+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.HTTP.Do(req)
	if e != nil {
		return errors.New("panel connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("panel refused request")
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
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
func (c *Client) Reconcile(ctx context.Context, m Manifest) (Report, error) {
	report := Report{Version: Version, Revision: m.Revision, Results: []Receipt{}}
	if m.Revision < c.State.Revision || len(m.Tunnels) > 32 {
		return report, errors.New("stale or oversized manifest")
	}
	if m.Revision == c.State.Revision && !reflect.DeepEqual(m.Tunnels, c.State.Tunnels) {
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
			if old.ID == t.ID && !reflect.DeepEqual(old, t) {
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
			r.PeerAlive = c.Network.Probe(ctx, t)
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
	return c.request(ctx, "POST", "/heartbeat", r, nil)
}
