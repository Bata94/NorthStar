package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/bata94/northstar/dns"
)

type DoQClient struct {
	tlsConf *tls.Config
	addr    string
	timeout time.Duration
}

func NewDoQClient(addr string, tlsServerName string, timeout int) *DoQClient {
	serverName := tlsServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			serverName = addr
		} else {
			serverName = host
		}
	}
	return &DoQClient{
		tlsConf: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"doq"},
		},
		addr:    addr,
		timeout: time.Duration(timeout) * time.Second,
	}
}

func (d *DoQClient) Query(ctx context.Context, msg *dns.Message) (*dns.Message, error) {
	packed := msg.Pack()

	conn, err := quic.DialAddr(ctx, d.addr, d.tlsConf, &quic.Config{
		HandshakeIdleTimeout: d.timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("doq dial: %w", err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq open stream: %w", err)
	}
	defer func() { _ = stream.Close() }()

	_ = stream.SetWriteDeadline(time.Now().Add(d.timeout))

	lenPref := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(lenPref, uint16(len(packed)))
	copy(lenPref[2:], packed)

	if _, err := stream.Write(lenPref); err != nil {
		return nil, fmt.Errorf("doq write: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(d.timeout))

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return nil, fmt.Errorf("doq read length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)

	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return nil, fmt.Errorf("doq read body: %w", err)
	}

	var reply dns.Message
	if err := reply.Parse(buf); err != nil {
		return nil, fmt.Errorf("doq parse: %w", err)
	}

	return &reply, nil
}
