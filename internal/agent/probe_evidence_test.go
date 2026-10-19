package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func evidenceReceipt(at time.Time, alive bool) Receipt {
	return Receipt{ID: "test", Applied: true, PeerAlive: alive, Probe: &ProbeEvidence{CheckedAt: at, BootID: "boot", Attempts: []ProbeAttempt{{Method: "tcp", Port: 443, Outcome: map[bool]string{true: "ok", false: "timeout"}[alive]}}}}
}
func TestProbeSelectionIsSparseAndRecordsRecovery(t *testing.T) {
	c := Client{}
	now := time.Now()
	r := evidenceReceipt(now, true)
	c.selectProbe(&r)
	if r.Probe == nil {
		t.Fatal("first baseline missing")
	}
	r = evidenceReceipt(now.Add(15*time.Second), true)
	c.selectProbe(&r)
	if r.Probe != nil {
		t.Fatal("healthy heartbeat logged")
	}
	r = evidenceReceipt(now.Add(20*time.Second), false)
	c.selectProbe(&r)
	if r.Probe == nil {
		t.Fatal("failure missing")
	}
	r = evidenceReceipt(now.Add(35*time.Second), false)
	c.selectProbe(&r)
	if r.Probe != nil {
		t.Fatal("duplicate failure logged")
	}
	r = evidenceReceipt(now.Add(40*time.Second), true)
	c.selectProbe(&r)
	if r.Probe == nil {
		t.Fatal("recovery missing")
	}
}
func TestFlappingHasHardRateLimit(t *testing.T) {
	c := Client{}
	count := 0
	now := time.Now()
	for i := 0; i < 100; i++ {
		r := evidenceReceipt(now.Add(time.Duration(i)*time.Millisecond), i%2 == 0)
		c.selectProbe(&r)
		if r.Probe != nil {
			count++
		}
	}
	if count != 12 {
		t.Fatalf("rate limit: %d", count)
	}
}
func TestProbeErrorsKeepOnlyClassifications(t *testing.T) {
	for err, want := range map[error]string{syscall.ECONNREFUSED: "connection_refused", syscall.ENETUNREACH: "network_unreachable", syscall.EHOSTUNREACH: "host_unreachable", errors.New("private://credential"): "probe_failed"} {
		if got := probeError(context.Background(), err); got != want {
			t.Fatal(got)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probeError(ctx, syscall.ECONNREFUSED) != "cycle_canceled" {
		t.Fatal("cycle cancellation lost")
	}
}
func TestProbeJournalRotatesAndRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	c := Client{Config: Config{StateFile: filepath.Join(dir, "state")}}
	path := c.Config.StateFile + ".probes.jsonl"
	if err := os.WriteFile(path, make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	r := evidenceReceipt(time.Now(), false)
	if err := c.recordProbe(r); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + ".previous"); err != nil || info.Size() != (1<<20)+1 {
		t.Fatal("rotation missing")
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) {
		t.Fatal("invalid sample")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(dir, "target"), path)
	if c.recordProbe(r) == nil {
		t.Fatal("symlink accepted")
	}
}
func TestDetailedProbeDoesNotTouchNetworkConfiguration(t *testing.T) {
	tunnel := sample()
	tunnel.PeerTCPPorts = []int{31006}
	runner := &probeRunner{tcpPort: 31006}
	alive, method, port, e := (Network{runner}).ProbeDetailed(context.Background(), tunnel)
	if !alive || method != "tcp" || port != 31006 || e == nil || len(e.Attempts) != 1 || e.Attempts[0].Outcome != "ok" {
		t.Fatal("missing evidence")
	}
	if len(runner.calls) != 0 {
		t.Fatal("probe mutated network")
	}
}
