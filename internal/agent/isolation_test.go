package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
)

type existingLinkRunner struct {
	fakeRunner
	existing Tunnel
}

func (f *existingLinkRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	b, e := f.fakeRunner.Run(ctx, name, args...)
	if reflect.DeepEqual(args, []string{"-j", "-d", "link", "show"}) {
		t := f.existing
		var l Link
		l.Name = t.Name()
		l.Alias = "nahan:" + t.ID
		l.Info.Kind = "gre"
		l.Info.Data.Local = t.Local
		l.Info.Data.Remote = t.Remote
		l.Info.Data.TTL = t.TTL
		l.Info.Data.IKey, _ = json.Marshal(t.Key)
		l.Info.Data.OKey = l.Info.Data.IKey
		return json.Marshal([]Link{l})
	}
	return b, e
}

func TestNewTunnelNeverMutatesExistingLink(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "new succeeds", true: "new fails"}[fail], func(t *testing.T) {
			old := sample()
			added := sample()
			added.ID = "22222222-2222-4222-8222-222222222222"
			added.Inner = "10.240.4.1/30"
			added.Peer = "10.240.4.2"
			added.Key++
			f := &existingLinkRunner{fakeRunner: fakeRunner{fail: fail}, existing: old}
			c := Client{Config: Config{StateFile: filepath.Join(t.TempDir(), "state.json")}, Network: Network{f}, State: Manifest{Revision: 1, Tunnels: []Tunnel{old}}}
			report, e := c.Reconcile(context.Background(), Manifest{Revision: 2, Tunnels: []Tunnel{old, added}})
			if e != nil {
				t.Fatal(e)
			}
			if len(report.Results) != 2 || !report.Results[0].Applied || !report.Results[0].PeerAlive {
				t.Fatal("existing tunnel lost its successful receipt")
			}
			if report.Results[1].Applied == fail {
				t.Fatal("new tunnel failure not represented independently")
			}
			for _, call := range f.calls {
				if len(call) < 2 || call[0] != "ip" || (call[1] != "link" && call[1] != "tunnel" && call[1] != "address") {
					continue
				}
				for _, arg := range call[2:] {
					if arg == old.Name() {
						t.Fatalf("existing interface mutated: %v", call)
					}
				}
			}
		})
	}
}
