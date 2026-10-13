package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testClient(t *testing.T) *Client {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	os.WriteFile(key, []byte(strings.Repeat("a", 40)), 0600)
	c, e := New(Config{Panel: "https://panel.example/api", ID: "11111111-1111-4111-8111-111111111111", TokenFile: key, StateFile: filepath.Join(dir, "state")})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func reply(status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"revision":1,"tunnels":[]}`))}
}
func TestOrderedIPFallback(t *testing.T) {
	c := testClient(t)
	calls := []string{}
	c.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		calls = append(calls, "primary")
		return nil, errors.New("network unavailable")
	})
	c.directHTTP = []*http.Client{{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, "ip1")
		if r.URL.Host != "panel.example" {
			t.Error("hostname lost")
		}
		return nil, errors.New("TLS certificate invalid")
	})}, {Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, "ip2")
		if r.Header.Get("Authorization") == "" {
			t.Error("credential missing")
		}
		return reply(200), nil
	})}}
	for i := 0; i < 2; i++ {
		if e := c.Verify(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if strings.Join(calls, ",") != "primary,ip1,ip2,ip2" {
		t.Fatal(calls)
	}
	if _, e := os.Stat(c.Config.StateFile); !os.IsNotExist(e) {
		t.Fatal("verification changed state")
	}
}
func TestAuthAndInvalidJSONAreTerminal(t *testing.T) {
	for _, status := range []int{401, 403, 409, 429, 200} {
		c := testClient(t)
		c.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
			r := reply(status)
			if status == 200 {
				r.Body = io.NopCloser(strings.NewReader("invalid"))
			}
			return r, nil
		})
		c.directHTTP = []*http.Client{{Transport: roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("terminal error retried"); return nil, nil })}}
		if c.Verify(context.Background()) == nil {
			t.Fatal("invalid response accepted")
		}
	}
}
func TestFallbackValidatesCertificate(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("credential sent before certificate validation") }))
	defer s.Close()
	u, _ := url.Parse(s.URL)
	panel, _ := url.Parse("https://panel.example:" + u.Port())
	clients, e := directClients(panel, []string{"127.0.0.1"})
	if e == nil || len(clients) != 0 {
		t.Fatal("loopback configured")
	}
	c := controlHTTP(nil)
	_, e = c.Get(s.URL)
	if e == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestProductionDefaultsAndSafeTransport(t *testing.T) {
	u, _ := url.Parse("https://pwaapi.nahanvpn.com/api")
	clients, e := directClients(u, nil)
	if e != nil || len(clients) != 2 {
		t.Fatal(e)
	}
	tr := clients[0].Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify || !tr.DisableKeepAlives || tr.Proxy != nil || tr.ForceAttemptHTTP2 {
		t.Fatal("unsafe transport")
	}
	for _, ips := range [][]string{{"10.0.0.1"}, {"http://152.53.172.146"}, {"152.53.172.146", "152.53.172.146"}} {
		if _, e := directClients(u, ips); e == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := testClient(t).Verify(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestPrivateCAIdentityAndIsolation(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Control Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	original := ControlRootPEM
	ControlRootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	defer func() { ControlRootPEM = original }()
	for _, name := range []string{ControlServerName, "impostor.example"} {
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, _ := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if name != ControlServerName {
				t.Error("credential exposed to wrong identity")
			}
			w.Write([]byte(`{}`))
		}))
		server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}}}
		server.StartTLS()
		panel, _ := url.Parse("https://pwaapi.nahanvpn.com/api")
		clients, e := directClients(panel, []string{"152.53.172.146"})
		if e != nil {
			t.Fatal(e)
		}
		tr := clients[0].Transport.(*http.Transport)
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		response, e := clients[0].Get("https://pwaapi.nahanvpn.com/api")
		if name == ControlServerName {
			if e != nil {
				t.Fatal(e)
			}
			response.Body.Close()
		} else if e == nil {
			response.Body.Close()
			t.Fatal("wrong control identity accepted")
		}
		server.Close()
	}
}

func TestPrimaryRetryDeadlineIsNotExtended(t *testing.T) {
	c := testClient(t)
	c.preferred = 1
	c.primaryRetry = time.Now().Add(30 * time.Second)
	deadline := c.primaryRetry
	c.directHTTP = []*http.Client{{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return reply(200), nil })}}
	c.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("primary probed too early"); return nil, nil })
	if e := c.Verify(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !deadline.Equal(c.primaryRetry) {
		t.Fatal("primary retry indefinitely deferred")
	}
}
