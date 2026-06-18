// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package resolver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func Serve(ctx context.Context, l config.Listener, upstream string, c cache.Cache, rateLimit int, staleAge int, pool *Pool, m *metrics.Metrics) error {
	addr := net.UDPAddr{Port: l.Port, IP: net.ParseIP(l.IP)}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Error("Error closing connection", "error", err)
		}
	}()

	slog.Info("UDP server listening", "addr", addr.String())

	var wg sync.WaitGroup
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			goto drain
		default:
		}

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			panic(fmt.Sprintf("failed to set read deadline: %v", err))
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleRequest(ctx, data, remoteAddr, conn, upstream, c, rateLimit, staleAge, pool, m)
		}()
	}

drain:
	slog.Info("Draining in-flight requests...")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("Drain timeout, forcing shutdown")
	}
	return nil
}

func ServeTCP(ctx context.Context, l config.Listener, upstream string, c cache.Cache, rateLimit int, staleAge int, pool *Pool, m *metrics.Metrics) error {
	addr := net.TCPAddr{Port: l.Port, IP: net.ParseIP(l.IP)}
	listener, err := net.ListenTCP("tcp", &addr)
	if err != nil {
		return err
	}
	defer func() {
		if err := listener.Close(); err != nil {
			slog.Error("Error closing TCP listener", "error", err)
		}
	}()

	slog.Info("TCP server listening", "addr", addr.String())

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			goto drain
		default:
		}

		if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			panic(fmt.Sprintf("failed to set TCP accept deadline: %v", err))
		}

		tcpConn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			handleTCPConnection(ctx, tcpConn, upstream, c, rateLimit, staleAge, pool, m)
		}()
	}

drain:
	slog.Info("Draining TCP connections...")
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		slog.Warn("TCP drain timeout, forcing shutdown")
	}
	return nil
}

type inflightKey struct {
	domain string
	qtype  uint16
}

type inflightCall struct {
	done  chan struct{}
	entry *cache.Entry
	err   error
	once  sync.Once
}

var (
	inflightMu    sync.Mutex
	inflightCalls = make(map[inflightKey]*inflightCall)
)

func clientEDNS(req *dns.Message) (size uint16, do bool) {
	for _, rr := range req.Additionals {
		if rr.Type == 41 {
			return rr.Class, rr.TTL&0x00008000 != 0
		}
	}
	return 512, false
}

func stripOPT(rrs []dns.ResourceRecord) []dns.ResourceRecord {
	var out []dns.ResourceRecord
	for _, rr := range rrs {
		if rr.Type != 41 {
			out = append(out, rr)
		}
	}
	return out
}

func handleTCPConnection(ctx context.Context, conn net.Conn, upstream string, c cache.Cache, rateLimit int, staleAge int, pool *Pool, m *metrics.Metrics) {
	ctxRead, cancelRead := context.WithCancel(ctx)
	defer cancelRead()

	go func() {
		select {
		case <-ctxRead.Done():
		case <-ctx.Done():
			_ = conn.Close()
		}
	}()

	defer func() {
		if err := conn.Close(); err != nil {
			slog.Error("Error closing TCP connection", "error", err)
		}
	}()

	m.ActiveHandlers.Inc()
	defer m.ActiveHandlers.Dec()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		slog.Error("Failed to set TCP read deadline", "error", err)
		return
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		slog.Warn("Failed to read TCP length", "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "parse_error"}).Inc()
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		slog.Warn("Failed to read TCP message", "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "parse_error"}).Inc()
		return
	}

	var req dns.Message
	if err := req.Parse(data); err != nil {
		slog.Warn("Failed to parse TCP request", "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "parse_error"}).Inc()
		return
	}

	if len(req.Questions) == 0 {
		slog.Warn("TCP request has no questions")
		return
	}

	q := req.Questions[0]
	maxPayload, do := clientEDNS(&req)

	m.QueriesTotal.With(prometheus.Labels{"qtype": strconv.Itoa(int(q.Type))}).Inc()

	if rateLimit > 0 {
		clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		key := fmt.Sprintf("northstar:ratelimit:%s:%d", clientIP, time.Now().Unix())
		val, err := c.Incr(ctx, key, time.Second)
		if err == nil && val > int64(rateLimit) {
			slog.Warn("Rate limit exceeded", "client", clientIP, "qps", rateLimit)
			m.ErrorsTotal.With(prometheus.Labels{"type": "rate_limited"}).Inc()
			resp := dns.Message{
				Header: dns.Header{
					ID:      req.Header.ID,
					Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0002,
					QDCount: 1,
				},
				Questions: req.Questions,
			}
			if err := writeTCPResponse(conn, resp.Pack()); err != nil {
				slog.Error("Error writing TCP SERVFAIL", "error", err)
			}
			return
		}
	}

	entry, err := resolve(ctx, q.Name, q.Type, upstream, c, maxPayload, "tcp", staleAge, pool, do, m)
	if err != nil {
		slog.Warn("Upstream error", "domain", q.Name, "type", q.Type, "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "servfail"}).Inc()
		resp := dns.Message{
			Header: dns.Header{
				ID:      req.Header.ID,
				Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0002,
				QDCount: 1,
			},
			Questions: req.Questions,
		}
		if err := writeTCPResponse(conn, resp.Pack()); err != nil {
			slog.Error("Error writing TCP SERVFAIL", "error", err)
		}
		return
	}

	answers, authorities, additionals := entry.CopyRecordsWithAdjustedTTL()

	additionals = append(additionals, dns.ResourceRecord{
		Name:  "",
		Type:  41,
		Class: maxPayload,
	})

	flags := req.Header.Flags & 0x7910
	flags |= 0x8000 | 0x0080 | entry.RCode
	if entry.AuthenticData {
		flags |= 0x0020
	}

	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authorities)),
			ARCount: uint16(len(additionals)),
		},
		Questions:   req.Questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}

	if err := writeTCPResponse(conn, resp.Pack()); err != nil {
		slog.Error("Error writing TCP response", "error", err)
	}
	slog.Debug("TCP query completed", "domain", q.Name, "type", q.Type, "answers", len(entry.Answers))
}

func writeTCPResponse(conn net.Conn, data []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	lenPref := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPref, uint16(len(data)))
	if _, err := conn.Write(lenPref); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func handleRequest(ctx context.Context, data []byte, remoteAddr *net.UDPAddr, conn *net.UDPConn, upstream string, c cache.Cache, rateLimit int, staleAge int, pool *Pool, m *metrics.Metrics) {
	m.ActiveHandlers.Inc()
	defer m.ActiveHandlers.Dec()

	var req dns.Message
	if err := req.Parse(data); err != nil {
		slog.Warn("Failed to parse request", "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "parse_error"}).Inc()
		return
	}

	if len(req.Questions) == 0 {
		slog.Warn("Request has no questions")
		return
	}

	q := req.Questions[0]
	maxPayload, do := clientEDNS(&req)

	m.QueriesTotal.With(prometheus.Labels{"qtype": strconv.Itoa(int(q.Type))}).Inc()

	if rateLimit > 0 {
		key := fmt.Sprintf("northstar:ratelimit:%s:%d", remoteAddr.IP, time.Now().Unix())
		val, err := c.Incr(ctx, key, time.Second)
		if err == nil && val > int64(rateLimit) {
			slog.Warn("Rate limit exceeded", "client", remoteAddr.IP, "qps", rateLimit)
			m.ErrorsTotal.With(prometheus.Labels{"type": "rate_limited"}).Inc()
			resp := dns.Message{
				Header: dns.Header{
					ID:      req.Header.ID,
					Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0002,
					QDCount: 1,
				},
				Questions: req.Questions,
			}
			if _, err := conn.WriteToUDP(resp.Pack(), remoteAddr); err != nil {
				slog.Error("Error writing SERVFAIL", "error", err)
			}
			return
		}
	}

	entry, err := resolve(ctx, q.Name, q.Type, upstream, c, maxPayload, "udp", staleAge, pool, do, m)
	if err != nil {
		slog.Warn("Upstream error", "domain", q.Name, "type", q.Type, "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "servfail"}).Inc()
		resp := dns.Message{
			Header: dns.Header{
				ID:      req.Header.ID,
				Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0002,
				QDCount: 1,
			},
			Questions: req.Questions,
		}
		if _, err := conn.WriteToUDP(resp.Pack(), remoteAddr); err != nil {
			slog.Error("Error writing SERVFAIL", "error", err)
		}
		return
	}

	answers, authorities, additionals := entry.CopyRecordsWithAdjustedTTL()

	additionals = append(additionals, dns.ResourceRecord{
		Name:  "",
		Type:  41,
		Class: maxPayload,
	})

	flags := req.Header.Flags & 0x7910
	flags |= 0x8000 | 0x0080 | entry.RCode
	if entry.AuthenticData {
		flags |= 0x0020
	}

	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   flags,
			QDCount: 1,
			ANCount: uint16(len(answers)),
			NSCount: uint16(len(authorities)),
			ARCount: uint16(len(additionals)),
		},
		Questions:   req.Questions,
		Answers:     answers,
		Authorities: authorities,
		Additionals: additionals,
	}

	respPacked := resp.Pack()
	if len(respPacked) > int(maxPayload) {
		slog.Debug("Response truncated", "domain", q.Name, "size", len(respPacked), "max", maxPayload)
		resp.Header.Flags |= 0x0200
		resp.Answers = nil
		resp.Authorities = nil
		resp.Additionals = nil
		resp.Header.ANCount = 0
		resp.Header.NSCount = 0
		resp.Header.ARCount = 0
		respPacked = resp.Pack()
	}

	if _, err := conn.WriteToUDP(respPacked, remoteAddr); err != nil {
		slog.Error("Error writing response", "error", err)
	}
	slog.Debug("Query completed", "domain", q.Name, "type", q.Type, "answers", len(entry.Answers))
}

func fetchFromUpstream(ctx context.Context, domain string, qtype uint16, maxPayload uint16, network string, pool *Pool, do bool, m *metrics.Metrics) (*cache.Entry, error) {
	start := time.Now()
	defer func() {
		m.UpstreamLatency.Observe(time.Since(start).Seconds())
	}()

	queryID := uint16(time.Now().UnixNano() & 0xFFFF)
	optTTL := uint32(0)
	if do {
		optTTL |= 0x00008000
	}
	msg := dns.Message{
		Header: dns.Header{
			ID:      queryID,
			Flags:   0x0100,
			QDCount: 1,
			ARCount: 1,
		},
		Questions: []dns.Question{{
			Name:  domain,
			Type:  qtype,
			Class: 1,
		}},
		Additionals: []dns.ResourceRecord{{
			Name:  "",
			Type:  41,
			Class: maxPayload,
			TTL:   optTTL,
		}},
	}
	query := msg.Pack()

	fwd, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire upstream conn: %w", err)
	}

	abort := make(chan struct{})
	defer close(abort)
	go func() {
		select {
		case <-ctx.Done():
			_ = fwd.Close()
		case <-abort:
		}
	}()

	isTCP := network == "tcp"

	if isTCP {
		lenPref := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(lenPref, uint16(len(query)))
		copy(lenPref[2:], query)
		query = lenPref
	}

	if err := fwd.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		pool.Release(fwd, err)
		return nil, fmt.Errorf("set upstream write deadline: %w", err)
	}
	if _, err := fwd.Write(query); err != nil {
		pool.Release(fwd, err)
		return nil, fmt.Errorf("forward to upstream: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	if err := fwd.SetReadDeadline(deadline); err != nil {
		pool.Release(fwd, err)
		return nil, fmt.Errorf("set upstream read deadline: %w", err)
	}

	var buf []byte
	if isTCP {
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(fwd, lenBuf); err != nil {
			pool.Release(fwd, err)
			return nil, fmt.Errorf("read upstream TCP length: %w", err)
		}
		msgLen := binary.BigEndian.Uint16(lenBuf)
		buf = make([]byte, msgLen)
		if _, err := io.ReadFull(fwd, buf); err != nil {
			pool.Release(fwd, err)
			return nil, fmt.Errorf("read upstream TCP message: %w", err)
		}
	} else {
		bufSize := int(maxPayload)
		if bufSize < 512 {
			bufSize = 512
		}
		rbuf := make([]byte, bufSize)
		n, err := fwd.Read(rbuf)
		if err != nil {
			pool.Release(fwd, err)
			return nil, fmt.Errorf("read upstream response: %w", err)
		}
		buf = rbuf[:n]
	}

	var reply dns.Message
	if err := reply.Parse(buf); err != nil {
		pool.Release(fwd, err)
		return nil, fmt.Errorf("parse upstream response: %w", err)
	}

	pool.Release(fwd, nil)
	entry := cache.NewEntry(domain, qtype, reply.Answers, reply.Authorities, stripOPT(reply.Additionals))
	entry.Flags = reply.Header.Flags
	entry.RCode = reply.Header.Flags & 0x000F
	entry.AuthenticData = reply.Header.Flags&0x0020 != 0
	return entry, nil
}

func refreshCache(call *inflightCall, ikey inflightKey, domain string, qtype uint16, c cache.Cache, maxPayload uint16, network string, pool *Pool, do bool, m *metrics.Metrics) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entry, err := fetchFromUpstream(ctx, domain, qtype, maxPayload, network, pool, do, m)
	if err == nil {
		if err := c.Set(ctx, entry); err != nil {
			slog.Warn("Background refresh cache set failed", "domain", domain, "type", qtype, "error", err)
		}
		call.entry = entry
	} else {
		slog.Warn("Background refresh failed", "domain", domain, "type", qtype, "error", err)
		call.err = err
	}
	call.once.Do(func() { close(call.done) })
	inflightMu.Lock()
	delete(inflightCalls, ikey)
	inflightMu.Unlock()
}

func resolve(ctx context.Context, domain string, qtype uint16, upstream string, c cache.Cache, maxPayload uint16, network string, staleAge int, pool *Pool, do bool, m *metrics.Metrics) (*cache.Entry, error) {
	m.CacheLookups.Inc()

	if entry, found := c.Peek(ctx, domain, qtype); found && !entry.Expired() {
		slog.Debug("Cache hit", "domain", domain, "type", qtype)
		m.CacheHits.Inc()
		return entry, nil
	}

	if staleAge > 0 {
		if stale, found := c.Peek(ctx, domain, qtype); found && stale.Expired() {
			expiredFor := time.Since(stale.ExpiresAt)
			if expiredFor < time.Duration(staleAge)*time.Second {
				slog.Debug("Serving stale entry, refreshing in background", "domain", domain, "type", qtype)
				ikey := inflightKey{domain, qtype}
				inflightMu.Lock()
				if _, exists := inflightCalls[ikey]; !exists {
					call := &inflightCall{done: make(chan struct{})}
					inflightCalls[ikey] = call
					inflightMu.Unlock()
					go refreshCache(call, ikey, domain, qtype, c, maxPayload, network, pool, do, m)
				} else {
					inflightMu.Unlock()
				}
				return stale, nil
			}
		}
	}

	ikey := inflightKey{domain, qtype}
	inflightMu.Lock()
	if call, ok := inflightCalls[ikey]; ok {
		inflightMu.Unlock()
		slog.Debug("Waiting for in-flight fetch", "domain", domain, "type", qtype)
		select {
		case <-call.done:
			if call.entry != nil {
				return call.entry, nil
			}
			inflightMu.Lock()
			delete(inflightCalls, ikey)
			inflightMu.Unlock()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	inflightCalls[ikey] = call
	inflightMu.Unlock()

	defer func() {
		call.once.Do(func() { close(call.done) })
		inflightMu.Lock()
		delete(inflightCalls, ikey)
		inflightMu.Unlock()
	}()

	entry, err := fetchFromUpstream(ctx, domain, qtype, maxPayload, network, pool, do, m)
	if err != nil {
		call.err = err
		return nil, err
	}
	if err := c.Set(ctx, entry); err != nil {
		slog.Warn("Cache set failed", "domain", domain, "type", qtype, "error", err)
	}
	call.entry = entry
	return entry, nil
}
