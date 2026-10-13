package agent

import (
	"context"
	"testing"
)

type inventoryRunner struct{ raw string }

func (r inventoryRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(r.raw), nil
}
func TestInventoryMultipleAddresses(t *testing.T) {
	n := Network{inventoryRunner{raw: `[{"ifname":"eth0","operstate":"UP","mtu":1500,"addr_info":[{"local":"192.0.2.1","prefixlen":24,"family":"inet","scope":"global"},{"local":"192.0.2.2","prefixlen":24,"family":"inet","scope":"global"},{"local":"2001:db8::1","prefixlen":64,"family":"inet6","scope":"global"},{"local":"127.0.0.1","prefixlen":8,"family":"inet","scope":"host"}],"stats64":{"rx":{"bytes":1024},"tx":{"bytes":2048}}}]`}}
	out, err := n.Inventory(context.Background())
	if err != nil || len(out.Interfaces) != 1 || len(out.Interfaces[0].Addresses) != 3 || out.Interfaces[0].RX.Bytes != 1024 {
		t.Fatalf("unexpected inventory: %+v, %v", out, err)
	}
}
func TestInventoryRejectsMalformedJSON(t *testing.T) {
	_, err := (Network{inventoryRunner{raw: "broken"}}).Inventory(context.Background())
	if err == nil {
		t.Fatal("expected parse error")
	}
}
