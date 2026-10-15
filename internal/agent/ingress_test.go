package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func policy() IngressPolicy {
	return IngressPolicy{ID: sample().ID, Port: 31010, Sources: []string{"152.53.172.146", "152.53.176.197"}}
}
func TestIngressRulesBoundedAndIPv6Closed(t *testing.T) {
	rules, e := ingressRules([]IngressPolicy{policy()})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(rules, "ip saddr 152.53.172.146") || !strings.Contains(rules, "th dport 31010 drop") || strings.Contains(rules, "flush ruleset") {
		t.Fatal(rules)
	}
	for _, edit := range []func(*IngressPolicy){func(p *IngressPolicy) { p.Port = 22 }, func(p *IngressPolicy) { p.Sources = []string{"0.0.0.0"} }, func(p *IngressPolicy) { p.Sources = []string{"1.2.3.4;reboot"} }, func(p *IngressPolicy) { p.Sources = nil }, func(p *IngressPolicy) { p.ID = "bad" }, func(p *IngressPolicy) { p.Sources = []string{"::1"} }} {
		p := policy()
		edit(&p)
		if _, e := ingressRules([]IngressPolicy{p}); e == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	if _, e := ingressRules([]IngressPolicy{policy(), policy()}); e == nil {
		t.Fatal("duplicate accepted")
	}
}

type ingressRunner struct {
	script         string
	existing, fail bool
	calls          int
}

func (r *ingressRunner) Run(context.Context, string, ...string) ([]byte, error) {
	r.calls++
	if !r.existing {
		return nil, errors.New("absent")
	}
	return nil, nil
}
func (r *ingressRunner) RunInput(_ context.Context, _ string, b []byte, _ ...string) ([]byte, error) {
	r.script = string(b)
	if r.fail {
		return nil, errors.New("failure")
	}
	return nil, nil
}
func TestIngressAtomicReplacement(t *testing.T) {
	r := &ingressRunner{existing: true}
	if e := (Network{r}).ApplyIngress(context.Background(), []IngressPolicy{policy()}); e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(r.script, "delete table inet nahan_ingress\n") {
		t.Fatal(r.script)
	}
	r.fail = true
	if e := (Network{r}).ApplyIngress(context.Background(), nil); e == nil {
		t.Fatal("failure hidden")
	}
}
func TestIngressValidationBeforeMutation(t *testing.T) {
	r := &ingressRunner{}
	p := policy()
	p.Port = 22
	if e := (Network{r}).ApplyIngress(context.Background(), []IngressPolicy{p}); e == nil || r.calls != 0 {
		t.Fatal("unsafe mutation")
	}
}

func TestIngressReceiptPersistenceAndRestart(t *testing.T) {
	runner := &ingressRunner{}
	config := Config{StateFile: filepath.Join(t.TempDir(), "state.json")}
	client := Client{Config: config, Network: Network{runner}}
	desired := Manifest{Revision: 1, Tunnels: []Tunnel{}, IngressPolicies: []IngressPolicy{policy()}}
	report, e := client.Reconcile(context.Background(), desired)
	if e != nil || !report.IngressApplied || report.IngressRuntimeVersion != 1 || client.State.Revision != 1 {
		t.Fatal(report, e)
	}
	restored := Client{Config: config, Network: Network{runner}}
	runner.script = ""
	if e = restored.Load(); e != nil || runner.script == "" {
		t.Fatal("startup did not restore restrictions", e)
	}
	runner.fail = true
	next := Manifest{Revision: 2, Tunnels: []Tunnel{}}
	if report, e = client.Reconcile(context.Background(), next); e == nil || report.IngressApplied || client.State.Revision != 1 {
		t.Fatal("failed apply acknowledged")
	}
	// A crash during removal must retain enough intent to retry safely.
	runner.fail = false
	if e = restored.Load(); e != nil || len(restored.State.IngressPolicies) != 1 {
		t.Fatal("lost removal intent", e)
	}
	if _, e = restored.Reconcile(context.Background(), next); e != nil {
		t.Fatal(e)
	}
	if e = restored.Load(); e != nil {
		t.Fatal(e)
	}
	next.IngressPolicies = []IngressPolicy{}
	if _, e = restored.Reconcile(context.Background(), next); e != nil {
		t.Fatal("nil/empty policy mismatch after restart", e)
	}
}
