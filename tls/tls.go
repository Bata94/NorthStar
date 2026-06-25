package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/bata94/northstar/config"
)

var certDir = "/etc/northstar"

func ServerConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if cfg.AutoSelfSigned && cfg.CertFile == "" && cfg.KeyFile == "" {
		cfg.CertFile = certDir + "/cert.pem"
		cfg.KeyFile = certDir + "/key.pem"
		if err := ensureSelfSigned(cfg.CertFile, cfg.KeyFile); err != nil {
			return nil, fmt.Errorf("auto self-signed: %w", err)
		}
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}

	minVer := tls.VersionTLS12
	switch strings.TrimSpace(cfg.MinVersion) {
	case "1.3":
		minVer = tls.VersionTLS13
	}

	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   uint16(minVer),
		NextProtos:   []string{"dot", "h2", "http/1.1"},
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("no valid CA certificates in %s", cfg.CAFile)
		}
		tc.ClientAuth = tls.RequireAndVerifyClientCert
		tc.ClientCAs = caPool
	}

	return tc, nil
}

func ClientConfig(cfg config.TLSConfig, serverName string) *tls.Config {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err == nil {
			caPool := x509.NewCertPool()
			if caPool.AppendCertsFromPEM(caCert) {
				tc.RootCAs = caPool
			}
		}
	}

	return tc
}

func ensureSelfSigned(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			return nil
		}
	}

	dir := certFile
	if idx := strings.LastIndex(dir, "/"); idx >= 0 {
		dir = dir[:idx]
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	slog.Info("Generating self-signed TLS certificate", "cert", certFile, "key", keyFile)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"northstar"},
			CommonName:   "northstar.local",
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "northstar.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer func() { _ = certOut.Close() }()
	if err := certOut.Chmod(0644); err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer func() { _ = keyOut.Close() }()
	if err := keyOut.Chmod(0600); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}

	return nil
}
