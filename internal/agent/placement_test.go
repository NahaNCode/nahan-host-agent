package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestPlacementSocketScopedSignatureAndPersistentKey(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	c := &Client{Config: Config{ID: "11111111-1111-4111-8111-111111111111", StateFile: filepath.Join(dir, "state.json"), PlacementSocket: filepath.Join(dir, "placement.sock")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closeSocket, err := c.StartPlacement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "placement.sock")
	if closeOther, e := c.StartPlacement(ctx); e == nil {
		closeOther()
		t.Fatal("overwrote a live placement socket")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("socket exposed")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	core := "22222222-2222-4222-8222-222222222222"
	res, err := client.Get("http://local/v1/placement?coreId=" + core)
	if err != nil {
		t.Fatal(err)
	}
	var proof struct {
		HostID    string `json:"hostId"`
		CoreID    string `json:"coreId"`
		IssuedAt  int64  `json:"issuedAt"`
		Signature string `json:"signature"`
	}
	err = json.NewDecoder(res.Body).Decode(&proof)
	res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	public, _ := base64.StdEncoding.DecodeString(c.Placement.PublicKey())
	signature, _ := base64.StdEncoding.DecodeString(proof.Signature)
	if proof.CoreID != core || proof.HostID != c.Config.ID || !ed25519.Verify(public, []byte(fmt.Sprintf("nahan-core-host-v1\n%s\n%s\n%d", proof.HostID, core, proof.IssuedAt)), signature) {
		t.Fatal("invalid scoped signature")
	}
	res, err = client.Get("http://local/v1/placement?coreId=invalid")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatal("invalid audience accepted")
	}
	key := c.Placement.PublicKey()
	closeSocket()
	closeSocket, err = c.StartPlacement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSocket()
	if key != c.Placement.PublicKey() {
		t.Fatal("placement key rotated on restart")
	}
}
