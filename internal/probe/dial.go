package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/kayphoon/tunnelflux/internal/config"
)

func probeTCP(ctx context.Context, ip string, port int, timeout time.Duration) (float64, error) {
	dialer := net.Dialer{Timeout: timeout}
	t0 := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return float64(time.Since(t0).Microseconds()) / 1000.0, nil
}

func probeQUIC(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) (float64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	t0 := time.Now()
	tlsServerName := quicServerName(serverName)
	conn, err := quic.DialAddr(ctx, net.JoinHostPort(ip, fmt.Sprint(port)), &tls.Config{
		ServerName: tlsServerName,
		// Cloudflare Tunnel QUIC edge presents a Cloudflare Origin certificate,
		// not a public-web PKI certificate. Keep certificate shape and ALPN
		// checks, but do not require the system public CA pool for this probe.
		InsecureSkipVerify: true,
		VerifyConnection:   verifyCloudflareTunnelEdge,
		NextProtos: []string{
			"argotunnel",
		},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
		EnableDatagrams:      true,
	})
	if err != nil {
		return 0, err
	}
	_ = conn.CloseWithError(0, "probe complete")
	return float64(time.Since(t0).Microseconds()) / 1000.0, nil
}

func verifyCloudflareTunnelEdge(cs tls.ConnectionState) error {
	if cs.NegotiatedProtocol != "argotunnel" {
		return fmt.Errorf("unexpected quic ALPN %q", cs.NegotiatedProtocol)
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("missing quic peer certificate")
	}
	leaf := cs.PeerCertificates[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("cloudflare origin certificate is outside validity window")
	}
	if !nameContains(leaf.Subject.Organization, "CloudFlare") ||
		!nameContains(leaf.Subject.OrganizationalUnit, "CloudFlare Origin CA") ||
		!nameContains(leaf.Issuer.OrganizationalUnit, "CloudFlare Origin") {
		return fmt.Errorf("unexpected cloudflare origin certificate subject=%q issuer=%q", leaf.Subject.String(), leaf.Issuer.String())
	}
	return nil
}

func nameContains(values []string, want string) bool {
	for _, v := range values {
		if strings.Contains(strings.ToLower(v), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

func quicServerName(serverName string) string {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" || strings.HasSuffix(serverName, ".v2.argotunnel.com") {
		return config.CloudflaredQUICServerName
	}
	return serverName
}
