package resolver

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/upstream"
)

func ServeDOT(ctx context.Context, addr string, tlscfg *tls.Config, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) error {
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = tcpListener.Close() }()

	slog.Warn("DoT server listening", "addr", addr)

	iteration := func(wg *sync.WaitGroup) error {
		tcpLn := tcpListener.(*net.TCPListener)
		if err := tcpLn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			slog.Error("Failed to set DoT accept deadline", "error", err)
			return nil
		}

		tcpConn, err := tcpLn.Accept()
		if err != nil {
			return err
		}

		tlsConn := tls.Server(tcpConn, tlscfg)
		if err := tlsConn.Handshake(); err != nil {
			slog.Debug("DoT handshake failed", "error", err)
			_ = tcpConn.Close()
			return nil
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleTCPConnection(ctx, tlsConn, group, c, runtimeCfg, m)
		}()
		return nil
	}

	return serveLoop(ctx, iteration, "Draining DoT connections...", "DoT drain timeout, forcing shutdown")
}
