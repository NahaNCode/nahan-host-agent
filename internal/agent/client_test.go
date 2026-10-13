package agent

import (
	"context"
	"path/filepath"
	"testing"
)

func TestReconcilePersistsAndRejectsMutation(t *testing.T) {
	f := &fakeRunner{}
	c := Client{Config: Config{StateFile: filepath.Join(t.TempDir(), "state.json")}, Network: Network{f}}
	m := Manifest{Revision: 1, Tunnels: []Tunnel{sample()}}
	if _, e := c.Reconcile(context.Background(), m); e != nil {
		t.Fatal(e)
	}
	if c.State.Revision != 1 {
		t.Fatal("revision not saved")
	}
	m.Tunnels[0].MTU = 1380
	m.Revision = 2
	count := len(f.calls)
	if _, e := c.Reconcile(context.Background(), m); e == nil {
		t.Fatal("technical mutation accepted")
	}
	if len(f.calls) != count {
		t.Fatal("mutated network on rejection")
	}
	if _, e := c.Reconcile(context.Background(), Manifest{Revision: 0}); e == nil {
		t.Fatal("stale revision accepted")
	}
}
func TestFailedApplyCanRetry(t *testing.T) {
	f := &fakeRunner{fail: true}
	c := Client{Config: Config{StateFile: filepath.Join(t.TempDir(), "state.json")}, Network: Network{f}}
	m := Manifest{Revision: 1, Tunnels: []Tunnel{sample()}}
	if _, e := c.Reconcile(context.Background(), m); e != nil {
		t.Fatal(e)
	}
	if c.State.Revision != 0 {
		t.Fatal("failed revision acknowledged")
	}
	f.fail = false
	if _, e := c.Reconcile(context.Background(), m); e != nil {
		t.Fatal(e)
	}
	if c.State.Revision != 1 {
		t.Fatal("retry failed")
	}
}
