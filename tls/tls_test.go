package tls

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/bata94/northstar/config"
)

func TestSelfSigned(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	if err := ensureSelfSigned(certFile, keyFile); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Fatal("cert file not created")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("key file not created")
	}

	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatal("invalid key pair:", err)
	}
}

func TestServerConfig(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	if err := ensureSelfSigned(certFile, keyFile); err != nil {
		t.Fatal(err)
	}

	tc, err := ServerConfig(config.TLSConfig{
		CertFile:       certFile,
		KeyFile:        keyFile,
		MinVersion:     "1.2",
		AutoSelfSigned: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tc == nil {
		t.Fatal("nil config")
	}
	if len(tc.Certificates) == 0 {
		t.Fatal("no certificates")
	}
}

func TestClientConfig(t *testing.T) {
	tc := ClientConfig(config.TLSConfig{}, "cloudflare-dns.com")
	if tc == nil {
		t.Fatal("nil config")
	}
	if tc.ServerName != "cloudflare-dns.com" {
		t.Fatalf("expected cloudflare-dns.com, got %s", tc.ServerName)
	}
}

func TestServerConfigAutoSelfSigned(t *testing.T) {
	orig := certDir
	certDir = t.TempDir()
	defer func() { certDir = orig }()

	tc, err := ServerConfig(config.TLSConfig{
		AutoSelfSigned: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tc == nil {
		t.Fatal("nil config")
	}
	if len(tc.Certificates) == 0 {
		t.Fatal("no certificates")
	}
}
