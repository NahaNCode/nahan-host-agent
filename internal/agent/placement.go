package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type PlacementSigner struct {
	key  ed25519.PrivateKey
	host string
}

func (p *PlacementSigner) PublicKey() string {
	return base64.StdEncoding.EncodeToString(p.key.Public().(ed25519.PublicKey))
}
func (p *PlacementSigner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	core := r.URL.Query().Get("coreId")
	if r.Method != http.MethodGet || r.URL.Path != "/v1/placement" || !UUID(core) {
		http.Error(w, "invalid request", 400)
		return
	}
	issued := time.Now().Unix()
	message := fmt.Sprintf("nahan-core-host-v1\n%s\n%s\n%d", p.host, core, issued)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"hostId": p.host, "coreId": core, "issuedAt": issued, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(p.key, []byte(message)))})
}

// The local socket issues scoped attestations, never panel or agent credentials.
func (c *Client) StartPlacement(ctx context.Context) (func(), error) {
	dir := filepath.Dir(c.Config.StateFile)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe placement directory")
	}
	keyPath := filepath.Join(dir, "placement.key")
	data, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, e
		}
		f, e := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, e = f.Write(key)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, closeErr
		}
		data = key
	} else if err != nil {
		return nil, err
	}
	info, err = os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || len(data) != ed25519.PrivateKeySize {
		return nil, errors.New("unsafe placement key")
	}
	key := ed25519.NewKeyFromSeed(data[:ed25519.SeedSize])
	if !key.Equal(ed25519.PrivateKey(data)) {
		return nil, errors.New("invalid placement key")
	}
	path := c.Config.PlacementSocket
	if path == "" {
		path = "/run/nahan-host-placement/placement.sock"
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid placement socket path")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	info, err = os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unsafe socket directory")
	}
	if info, e := os.Lstat(path); e == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("unsafe placement socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, errors.New("placement socket already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return nil, errors.New("placement socket unavailable")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	signer := &PlacementSigner{key: key, host: c.Config.ID}
	server := &http.Server{Handler: signer, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
	c.Placement = signer
	go server.Serve(listener)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	return func() { close(done); server.Close(); os.Remove(path) }, nil
}
