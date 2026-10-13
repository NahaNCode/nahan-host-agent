package agent

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// Run only inside a disposable network namespace, never on a server's main network.
func TestIsolatedKernelLifecycle(t *testing.T) {
	if os.Getenv("NAHAN_ISOLATED_NETWORK") != "1" {
		t.Skip("requires isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r := ExecRunner{}
	run := func(args ...string) []byte {
		b, e := r.Run(ctx, "ip", args...)
		if e != nil {
			t.Fatalf("ip %v: %v", args, e)
		}
		return b
	}
	run("link", "set", "lo", "up")
	run("link", "add", "wan", "type", "dummy")
	run("address", "add", "192.0.2.1/24", "dev", "wan")
	run("link", "set", "wan", "up")
	run("tunnel", "add", "oldgre", "mode", "gre", "local", "192.0.2.1", "remote", "198.51.100.1", "ttl", "255")
	run("address", "add", "10.146.0.1/30", "dev", "oldgre")
	run("link", "set", "oldgre", "up")
	old := run("-j", "-d", "link", "show", "oldgre")
	before := run("-j", "-4", "route", "show")
	n := Network{r}
	s := sample()
	if e := n.Apply(ctx, s); e != nil {
		t.Fatal(e)
	}
	if e := n.Apply(ctx, s); e != nil {
		t.Fatalf("idempotence: %v", e)
	}
	if !bytes.Equal(old, run("-j", "-d", "link", "show", "oldgre")) {
		t.Fatal("existing GRE changed")
	}
	if e := n.Remove(ctx, s); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, run("-j", "-4", "route", "show")) {
		t.Fatal("routes not restored")
	}
	overlap := s
	overlap.Inner = "10.146.0.1/30"
	overlap.Peer = "10.146.0.2"
	if e := n.Apply(ctx, overlap); e == nil {
		t.Fatal("existing GRE subnet overlap accepted")
	}
	if !bytes.Equal(old, run("-j", "-d", "link", "show", "oldgre")) {
		t.Fatal("protected GRE changed after rejection")
	}
}
