package agent

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	owned bool
	fail  bool
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if reflect.DeepEqual(args, []string{"-j", "-d", "link", "show"}) {
		if f.owned {
			return []byte(`[{"ifname":"nhg111111111111","ifalias":"foreign","linkinfo":{"info_kind":"gre"}}]`), nil
		}
		return []byte(`[]`), nil
	}
	if len(args) > 2 && args[2] == "route" {
		return []byte(`[{"dst":"default","dev":"eth0"}]`), nil
	}
	if len(args) > 2 && args[2] == "address" {
		return []byte(`[{"ifname":"eth0","addr_info":[{"local":"192.0.2.1"}]}]`), nil
	}
	if f.fail && args[0] == "address" {
		return nil, errors.New("fail")
	}
	return []byte(`[]`), nil
}
func sample() Tunnel {
	return Tunnel{ID: "11111111-1111-4111-8111-111111111111", Local: "192.0.2.1", Remote: "198.51.100.1", Inner: "10.240.0.1/30", Peer: "10.240.0.2", Key: 98765, MTU: 1400, TTL: 64}
}
func TestValidation(t *testing.T) {
	s := sample()
	if Validate(s) != nil {
		t.Fatal("sample invalid")
	}
	for _, edit := range []func(*Tunnel){func(s *Tunnel) { s.ID = "../../etc" }, func(s *Tunnel) { s.Key = 0 }, func(s *Tunnel) { s.Inner = "10.240.0.0/30" }, func(s *Tunnel) { s.Local = ";reboot" }, func(s *Tunnel) { s.Peer = "10.240.0.3" }} {
		x := s
		edit(&x)
		if Validate(x) == nil {
			t.Fatal("unsafe input accepted")
		}
	}
}
func TestForeignOwnership(t *testing.T) {
	f := &fakeRunner{owned: true}
	n := Network{f}
	if n.Apply(context.Background(), sample()) == nil {
		t.Fatal("foreign link modified")
	}
	if len(f.calls) != 1 {
		t.Fatal("network mutation after collision")
	}
	if n.Remove(context.Background(), sample()) == nil {
		t.Fatal("foreign link deleted")
	}
}
func TestNoDefaultRouteMutation(t *testing.T) {
	f := &fakeRunner{}
	if e := (Network{f}).Apply(context.Background(), sample()); e != nil {
		t.Fatal(e)
	}
	for _, c := range f.calls {
		if len(c) > 2 && c[1] == "route" {
			t.Fatal("explicit route mutation")
		}
	}
}
func TestPartialRollback(t *testing.T) {
	f := &fakeRunner{fail: true}
	if (Network{f}).Apply(context.Background(), sample()) == nil {
		t.Fatal("failure ignored")
	}
	last := f.calls[len(f.calls)-1]
	if !reflect.DeepEqual(last, []string{"ip", "link", "del", "dev", sample().Name()}) {
		t.Fatal(last)
	}
}
