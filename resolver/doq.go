package resolver

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/upstream"
)

func ServeDOQ(ctx context.Context, addr string, tlscfg *tls.Config, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer func() { _ = udpConn.Close() }()

	// clone TLS config with ALPN for DoQ
	tc := tlscfg.Clone()
	tc.NextProtos = []string{"doq"}

	listener, err := quic.Listen(udpConn, tc, &quic.Config{
		Allow0RTT:          false,
		MaxIncomingStreams: 1000,
	})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	slog.Warn("DoQ server listening", "addr", addr)

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleDOQConn(ctx, conn, group, c, runtimeCfg, m)
		}()
	}
}

func handleDOQConn(ctx context.Context, conn *quic.Conn, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) {
	defer func() { _ = conn.CloseWithError(0, "") }()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		go func() {
			_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
			_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))

			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				_ = stream.Close()
				return
			}
			msgLen := binary.BigEndian.Uint16(lenBuf)

			data := make([]byte, msgLen)
			if _, err := io.ReadFull(stream, data); err != nil {
				_ = stream.Close()
				return
			}

			var req dns.Message
			if err := req.Parse(data); err != nil {
				slog.Warn("Failed to parse DoQ request", "error", err)
				_ = stream.Close()
				return
			}

			if len(req.Questions) == 0 {
				_ = stream.Close()
				return
			}

			clientIP := conn.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}

			maxPayload, do := clientEDNS(&req)

			send := func(resp []byte) error {
				lenPref := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(lenPref, uint16(len(resp)))
				copy(lenPref[2:], resp)
				_, err := stream.Write(lenPref)
				_ = stream.Close()
				return err
			}

			processQuery(ctx, &req, "tcp", clientIP, maxPayload, do, send, group, c, runtimeCfg, m)
		}()
	}
}
