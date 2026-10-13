package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"time"
)

var credentialPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)

// Only a public root certificate is distributed. Private issuing keys are never embedded.
//
//go:embed control-root.pem
var ControlRootPEM []byte

const ControlServerName = "control.nahan.internal"
const EndpointSetVersion = 1

func validCredential(token string) bool { return credentialPattern.MatchString(token) }

// A fresh bounded HTTP/1.1 connection avoids retaining a blackholed HTTP/2
// session. Both DNS and IP routes always verify the original HTTPS hostname.
func controlHTTP(dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DialContext = (&net.Dialer{Timeout: 4 * time.Second}).DialContext
	if dial != nil {
		transport.DialContext = dial
	}
	transport.TLSHandshakeTimeout = 4 * time.Second
	transport.ResponseHeaderTimeout = 8 * time.Second
	return &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func directClients(panel *url.URL, ips []string) ([]*http.Client, error) {
	if ips == nil && panel.Hostname() == "pwaapi.nahanvpn.com" {
		ips = []string{"152.53.172.146", "152.53.176.197"}
	}
	if len(ips) > 8 {
		return nil, errors.New("at most eight direct IPs allowed")
	}
	port := panel.Port()
	if port == "" {
		port = "443"
	}
	var clients []*http.Client
	seen := map[string]bool{}
	for _, value := range ips {
		ip, e := netip.ParseAddr(value)
		if e != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" || ip.Is4In6() || seen[value] {
			return nil, errors.New("invalid public direct IP")
		}
		seen[value] = true
		address := net.JoinHostPort(ip.String(), port)
		client := controlHTTP(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, address)
		})
		if panel.Hostname() == "pwaapi.nahanvpn.com" {
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(ControlRootPEM) {
				return nil, errors.New("invalid control trust root")
			}
			client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: ControlServerName}
		}
		clients = append(clients, client)
	}
	return clients, nil
}
