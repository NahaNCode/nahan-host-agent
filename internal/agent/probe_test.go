package agent

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

type probeRunner struct {
	existingLinkRunner
	tcpPort  int
	attempts []int
	failPing bool
}

func (p *probeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "ping" && p.failPing {
		return nil, errors.New("ICMP filtered")
	}
	return p.existingLinkRunner.Run(ctx, name, args...)
}
func (p *probeRunner) ProbeTCP(ctx context.Context, tunnel Tunnel, port int) bool {
	p.attempts = append(p.attempts, port)
	return port == p.tcpPort && ctx.Err() == nil
}

func TestTCPProbeDoesNotConfuseFilteredICMPWithBrokenTunnel(t *testing.T) {
	tunnel := sample()
	tunnel.PeerTCPPorts = []int{31006, 31011}
	runner := &probeRunner{failPing: true, tcpPort: 31011}
	alive, method, port := (Network{runner}).ProbeWithEvidence(context.Background(), tunnel)
	if !alive || method != "tcp" || port != 31011 || !reflect.DeepEqual(runner.attempts, []int{31006, 31011}) {
		t.Fatalf("wrong TCP evidence: %v %s %d", alive, method, port)
	}
	runner.tcpPort = 0
	if alive, _, _ := (Network{runner}).ProbeWithEvidence(context.Background(), tunnel); alive {
		t.Fatal("dead peer considered healthy")
	}
	runner.failPing = false
	if alive, method, _ := (Network{runner}).ProbeWithEvidence(context.Background(), tunnel); !alive || method != "icmp" {
		t.Fatal("ICMP fallback lost")
	}
}

func TestProbeMetadataUpdateNeverRecreatesExistingGRE(t *testing.T) {
	before := sample()
	after := before
	after.PeerTCPPorts = []int{31006}
	runner := &probeRunner{existingLinkRunner: existingLinkRunner{existing: before}, tcpPort: 31006, failPing: true}
	client := Client{Config: Config{StateFile: filepath.Join(t.TempDir(), "state.json")}, Network: Network{runner}, State: Manifest{Revision: 1, Tunnels: []Tunnel{before}}}
	report, err := client.Reconcile(context.Background(), Manifest{Revision: 1, Tunnels: []Tunnel{after}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || !report.Results[0].PeerAlive || report.Results[0].HealthMethod != "tcp" || report.Results[0].HealthPort != 31006 {
		t.Fatal("missing TCP receipt")
	}
	for _, call := range runner.calls {
		if len(call) > 2 && call[0] == "ip" && (call[1] == "link" || call[1] == "tunnel" || call[1] == "address") {
			t.Fatalf("GRE mutated for probe metadata: %v", call)
		}
	}
}

func TestTCPProbeValidationAndCanceledContext(t *testing.T) {
	for _, ports := range [][]int{{0}, {-1}, {65536}, {80, 80}, {80, 81, 82, 83}} {
		tunnel := sample()
		tunnel.PeerTCPPorts = ports
		if Validate(tunnel) == nil {
			t.Fatalf("unsafe probe ports accepted: %v", ports)
		}
	}
	tunnel := sample()
	tunnel.PeerTCPPorts = []int{31006}
	runner := &probeRunner{failPing: true, tcpPort: 31006}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if alive, _, _ := (Network{runner}).ProbeWithEvidence(ctx, tunnel); alive || len(runner.attempts) != 0 {
		t.Fatal("canceled probe continued")
	}
}
