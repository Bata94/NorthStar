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
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bata94/northstar/cache"
	"github.com/bata94/northstar/config"
	"github.com/bata94/northstar/dns"
	"github.com/bata94/northstar/hooks"
	"github.com/bata94/northstar/metrics"
	"github.com/bata94/northstar/upstream"
	"github.com/prometheus/client_golang/prometheus"
)

var soReusePort = func() int {
	if runtime.GOOS == "darwin" {
		return 0x0200
	}
	return 0x0F
}()

func listenConfig(reusePort bool) net.ListenConfig {
	if !reusePort {
		return net.ListenConfig{}
	}
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			if err := c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			}); err != nil {
				return err
			}
			return opErr
		},
	}
}

func Serve(ctx context.Context, l config.Listener, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) error {
	addr := net.UDPAddr{Port: l.Port, IP: net.ParseIP(l.IP)}
	lc := listenConfig(l.ReusePort)
	pc, err := lc.ListenPacket(ctx, "udp", addr.String())
	if err != nil {
		return err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("unexpected packet conn type")
	}

	defer func() {
		if err := conn.Close(); err != nil {
			slog.Error("Error closing connection", "error", err)
		}
	}()

	slog.Warn("UDP server listening", "addr", addr.String())

	buf := make([]byte, 1500)
	iteration := func(wg *sync.WaitGroup) error {
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			slog.Error("Failed to set UDP read deadline", "error", err)
			return nil
		}

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleRequest(ctx, data, remoteAddr, conn, group, c, runtimeCfg, m)
		}()
		return nil
	}

	return serveLoop(ctx, iteration, "Draining in-flight requests...", "Drain timeout, forcing shutdown")
}

func ServeTCP(ctx context.Context, l config.Listener, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics, maxTCPConns int) error {
	addr := net.TCPAddr{Port: l.Port, IP: net.ParseIP(l.IP)}
	lc := listenConfig(l.ReusePort)
	tcpListener, err := lc.Listen(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	listener, ok := tcpListener.(*net.TCPListener)
	if !ok {
		return fmt.Errorf("unexpected tcp listener type")
	}

	defer func() {
		if err := listener.Close(); err != nil {
			slog.Error("Error closing TCP listener", "error", err)
		}
	}()

	slog.Warn("TCP server listening", "addr", addr.String())

	iteration := func(wg *sync.WaitGroup) error {
		if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
			slog.Error("Failed to set TCP accept deadline", "error", err)
			return nil
		}

		tcpConn, err := listener.Accept()
		if err != nil {
			return err
		}

		clientIP := tcpConn.RemoteAddr().String()
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}

		if maxTCPConns > 0 && tcpTracker.inc(clientIP) > int64(maxTCPConns) {
			tcpTracker.dec(clientIP)
			slog.Warn("TCP connection limit exceeded", "client", clientIP, "limit", maxTCPConns)
			_ = tcpConn.Close()
			return nil
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer tcpTracker.dec(clientIP)
			handleTCPConnection(ctx, tcpConn, group, c, runtimeCfg, m)
		}()
		return nil
	}

	return serveLoop(ctx, iteration, "Draining TCP connections...", "TCP drain timeout, forcing shutdown")
}

func serveLoop(ctx context.Context, iteration func(*sync.WaitGroup) error, drainMsg, timeoutMsg string) error {
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			goto drain
		default:
		}

		if err := iteration(&wg); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
	}

drain:
	if drainMsg != "" {
		slog.Warn(drainMsg)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		if timeoutMsg != "" {
			slog.Error(timeoutMsg)
		} else {
			slog.Error("Drain timeout, forcing shutdown")
		}
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

type tcpConnTracker struct {
	mu    sync.Mutex
	conns map[string]int64
}

func (t *tcpConnTracker) inc(ip string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[ip]++
	return t.conns[ip]
}

func (t *tcpConnTracker) dec(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns[ip]--
	if t.conns[ip] <= 0 {
		delete(t.conns, ip)
	}
}

var (
	inflightMu    sync.Mutex
	inflightCalls = make(map[inflightKey]*inflightCall)
	pipelinePtr   atomic.Pointer[hooks.Pipeline]
	tcpTracker    = &tcpConnTracker{conns: make(map[string]int64)}
)

func SetPipeline(p *hooks.Pipeline) {
	pipelinePtr.Store(p)
}

func clientEDNS(req *dns.Message) (size uint16, do bool, version uint8) {
	for _, rr := range req.Additionals {
		if rr.Type == dns.TypeOPT {
			version = uint8(rr.TTL >> 16)
			return rr.Class, rr.TTL&0x00008000 != 0, version
		}
	}
	return 512, false, 0
}

func stripOPT(rrs []dns.ResourceRecord) []dns.ResourceRecord {
	var out []dns.ResourceRecord
	for _, rr := range rrs {
		if rr.Type != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

func handleTCPConnection(ctx context.Context, conn net.Conn, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) {
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

	clientIP := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	maxPayload, do, version := clientEDNS(&req)
	send := func(resp []byte) error {
		return writeTCPResponse(conn, resp)
	}
	processQuery(ctx, &req, "tcp", clientIP, maxPayload, do, version, send, group, c, runtimeCfg, m)
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

func processQuery(ctx context.Context, req *dns.Message, network, clientIP string, maxPayload uint16, do bool, version uint8, send func([]byte) error, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) {
	if version > 0 {
		slog.Warn("Unsupported EDNS version", "version", version)
		resp := buildBADVERSPacket(req, maxPayload)
		if err := send(resp); err != nil {
			slog.Error("Error sending BADVERS", "error", err)
		}
		return
	}

	q := req.Questions[0]
	if q.Class != 1 {
		slog.Warn("Non-IN class query refused", "class", q.Class, "domain", q.Name)
		sendRefused(req, send)
		return
	}
	m.QueriesTotal.With(prometheus.Labels{"qtype": strconv.Itoa(int(q.Type))}).Inc()

	pipeline := pipelinePtr.Load()
	if pipeline == nil {
		slog.Error("Pipeline not initialized")
		return
	}

	hookCtx := &hooks.Context{
		Ctx:       ctx,
		Request:   req,
		ClientIP:  clientIP,
		Network:   network,
		Cache:     c,
		Metrics:   m,
		Send:      send,
		StartTime: time.Now(),
	}

	if err := pipeline.Run(hooks.PreResolve, hookCtx); err != nil {
		return
	}

	entry, upstreamName, err := resolve(ctx, q.Name, q.Type, group, c, maxPayload, network, runtimeCfg, do, m, hookCtx.ECSData, hookCtx.PreferredUpstream)
	if err != nil {
		slog.Error("Upstream error", "domain", q.Name, "type", q.Type, "error", err)
		m.ErrorsTotal.With(prometheus.Labels{"type": "servfail"}).Inc()
		sendServfail(req, send)
		return
	}
	hookCtx.Entry = entry
	hookCtx.Upstream = upstreamName

	if err := pipeline.Run(hooks.PostResolve, hookCtx); err != nil {
		return
	}

	answers, authorities, additionals := entry.CopyRecordsWithAdjustedTTL()

	optTTLResp := uint32(0)
	if do {
		optTTLResp |= 0x00008000
	}
	additionals = append(additionals, dns.ResourceRecord{
		Name:  "",
		Type:  dns.TypeOPT,
		Class: maxPayload,
		TTL:   optTTLResp,
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
	hookCtx.Response = &resp

	if err := pipeline.Run(hooks.PreResponse, hookCtx); err != nil {
		return
	}

	respPacked := packResponseWithTruncation(&resp, maxPayload)
	if len(respPacked) > int(maxPayload) {
		slog.Warn("Response truncated (no records fit)", "domain", q.Name, "size", len(respPacked), "max", maxPayload)
	}

	if err := send(respPacked); err != nil {
		slog.Error("Error writing response", "error", err)
		return
	}
	slog.Debug("Query completed", "domain", q.Name, "type", q.Type, "answers", len(entry.Answers))

	if err := pipeline.Run(hooks.PostResponse, hookCtx); err != nil {
		slog.Error("PostResponse hook error", "error", err)
	}
}

func buildBADVERSPacket(req *dns.Message, maxPayload uint16) []byte {
	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   0x8000,
			QDCount: 1,
		},
		Questions: req.Questions,
	}
	resp.Header.ARCount = 1
	resp.Additionals = append(resp.Additionals, dns.ResourceRecord{
		Name:  "",
		Type:  dns.TypeOPT,
		Class: maxPayload,
		TTL:   uint32(dns.RcodeBADVERS>>4) << 24,
	})
	return resp.Pack()
}

func sendServfail(req *dns.Message, send func([]byte) error) {
	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0002,
			QDCount: 1,
		},
		Questions: req.Questions,
	}
	packed := resp.Pack()
	if err := send(packed); err != nil {
		slog.Error("Error writing SERVFAIL", "error", err)
	}
}

func sendRefused(req *dns.Message, send func([]byte) error) {
	resp := dns.Message{
		Header: dns.Header{
			ID:      req.Header.ID,
			Flags:   req.Header.Flags & ^uint16(0x002F) | 0x8000 | 0x0005,
			QDCount: 1,
		},
		Questions: req.Questions,
	}
	packed := resp.Pack()
	if err := send(packed); err != nil {
		slog.Error("Error writing REFUSED", "error", err)
	}
}

func packResponseWithTruncation(resp *dns.Message, maxPayload uint16) []byte {
	packed := resp.Pack()
	if len(packed) <= int(maxPayload) {
		return packed
	}
	resp.Header.Flags |= 0x0200

	if len(resp.Additionals) > 0 {
		lastOpt := -1
		for i := range resp.Additionals {
			if resp.Additionals[i].Type == dns.TypeOPT {
				lastOpt = i
				break
			}
		}
		var tmp []dns.ResourceRecord
		if lastOpt >= 0 {
			tmp = append(tmp, resp.Additionals[lastOpt])
		}
		saved := resp.Additionals
		resp.Additionals = tmp
		resp.Header.ARCount = uint16(len(tmp))
		packed = resp.Pack()
		if len(packed) <= int(maxPayload) {
			return packed
		}
		resp.Additionals = saved
		resp.Header.ARCount = uint16(len(saved))
	}

	for len(resp.Answers) > 0 {
		savedLen := len(resp.Answers)
		probe := resp.Answers[:len(resp.Answers)-1]
		resp.Answers = probe
		resp.Header.ANCount = uint16(len(probe))
		packed = resp.Pack()
		if len(packed) <= int(maxPayload) {
			return packed
		}
		if len(resp.Answers) == savedLen {
			break
		}
	}

	resp.Answers = nil
	resp.Header.ANCount = 0

	for len(resp.Authorities) > 0 {
		savedLen := len(resp.Authorities)
		probe := resp.Authorities[:len(resp.Authorities)-1]
		resp.Authorities = probe
		resp.Header.NSCount = uint16(len(probe))
		packed = resp.Pack()
		if len(packed) <= int(maxPayload) {
			return packed
		}
		if len(resp.Authorities) == savedLen {
			break
		}
	}

	resp.Authorities = nil
	resp.Header.NSCount = 0

	for len(resp.Additionals) > 0 {
		savedLen := len(resp.Additionals)
		probe := resp.Additionals[:len(resp.Additionals)-1]
		resp.Additionals = probe
		resp.Header.ARCount = uint16(len(probe))
		packed = resp.Pack()
		if len(packed) <= int(maxPayload) {
			return packed
		}
		if len(resp.Additionals) == savedLen {
			break
		}
	}

	resp.Additionals = nil
	resp.Header.ARCount = 0
	return resp.Pack()
}

func handleRequest(ctx context.Context, data []byte, remoteAddr *net.UDPAddr, conn *net.UDPConn, group *upstream.Group, c cache.Cache, runtimeCfg *config.RuntimeConfig, m *metrics.Metrics) {
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

	clientIP := remoteAddr.IP.String()
	maxPayload, do, version := clientEDNS(&req)
	send := func(resp []byte) error {
		_, err := conn.WriteToUDP(resp, remoteAddr)
		return err
	}
	processQuery(ctx, &req, "udp", clientIP, maxPayload, do, version, send, group, c, runtimeCfg, m)
}

func fetchFromUpstream(ctx context.Context, domain string, qtype uint16, maxPayload uint16, network string, u *upstream.Upstream, do bool, m *metrics.Metrics, ttlMin, ttlMax, negativeTTL int, ecsData []byte) (*cache.Entry, error) {
	start := time.Now()
	defer func() {
		m.UpstreamLatency.WithLabelValues(u.Name).Observe(time.Since(start).Seconds())
	}()

	queryID := uint16(time.Now().UnixNano() & 0xFFFF)
	optTTL := uint32(0)
	if do {
		optTTL |= 0x00008000
	}
	optRdata := append([]byte(nil), ecsData...)

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
			Name:     "",
			Type:     dns.TypeOPT,
			Class:    maxPayload,
			TTL:      optTTL,
			RDLength: uint16(len(optRdata)),
			RData:    optRdata,
		}},
	}
	query := msg.Pack()

	if u.DoQ != nil {
		reply, err := u.DoQ.Query(ctx, &msg)
		if err != nil {
			return nil, err
		}
		u.RecordLatency(time.Since(start))
		u.ReportSuccess()
		m.UpstreamQueries.WithLabelValues(u.Name).Inc()
		rcode := reply.Header.Flags & 0x000F
		entry := cache.NewEntry(domain, qtype, rcode, reply.Answers, reply.Authorities, stripOPT(reply.Additionals), ttlMin, ttlMax, negativeTTL)
		entry.Flags = reply.Header.Flags
		entry.RCode = reply.Header.Flags & 0x000F
		entry.AuthenticData = reply.Header.Flags&0x0020 != 0
		return entry, nil
	}

	if u.DoH != nil {
		reply, err := u.DoH.Query(ctx, &msg)
		if err != nil {
			return nil, err
		}
		u.RecordLatency(time.Since(start))
		u.ReportSuccess()
		m.UpstreamQueries.WithLabelValues(u.Name).Inc()
		rcode := reply.Header.Flags & 0x000F
		entry := cache.NewEntry(domain, qtype, rcode, reply.Answers, reply.Authorities, stripOPT(reply.Additionals), ttlMin, ttlMax, negativeTTL)
		entry.Flags = reply.Header.Flags
		entry.RCode = reply.Header.Flags & 0x000F
		entry.AuthenticData = reply.Header.Flags&0x0020 != 0
		return entry, nil
	}

	var pool *Pool
	if network == "tcp" || u.Config.TCPOnly {
		pool = u.TCPPool
	} else {
		pool = u.UDPPool
	}

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

	timeout := u.AdaptiveTimeout()
	writeTO := timeout
	if writeTO < 2*time.Second {
		writeTO = 2 * time.Second
	}

	if err := fwd.SetWriteDeadline(time.Now().Add(writeTO)); err != nil {
		pool.Release(fwd, err)
		return nil, fmt.Errorf("set upstream write deadline: %w", err)
	}
	if _, err := fwd.Write(query); err != nil {
		pool.Release(fwd, err)
		return nil, fmt.Errorf("forward to upstream: %w", err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
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
	u.RecordLatency(time.Since(start))
	u.ReportSuccess()
	m.UpstreamQueries.WithLabelValues(u.Name).Inc()
	rcode := reply.Header.Flags & 0x000F
	entry := cache.NewEntry(domain, qtype, rcode, reply.Answers, reply.Authorities, stripOPT(reply.Additionals), ttlMin, ttlMax, negativeTTL)
	entry.Flags = reply.Header.Flags
	entry.RCode = reply.Header.Flags & 0x000F
	entry.AuthenticData = reply.Header.Flags&0x0020 != 0
	return entry, nil
}

func refreshCache(call *inflightCall, ikey inflightKey, domain string, qtype uint16, c cache.Cache, maxPayload uint16, network string, group *upstream.Group, do bool, m *metrics.Metrics, ttlMin, ttlMax, negativeTTL int, ecsData []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	u, err := group.Select(ctx, domain)
	if err != nil {
		slog.Error("Background refresh upstream selection failed", "domain", domain, "type", qtype, "error", err)
		call.err = err
		call.once.Do(func() { close(call.done) })
		inflightMu.Lock()
		delete(inflightCalls, ikey)
		inflightMu.Unlock()
		return
	}

	entry, err := fetchFromUpstream(ctx, domain, qtype, maxPayload, network, u, do, m, ttlMin, ttlMax, negativeTTL, ecsData)
	if err == nil {
		if err := c.Set(ctx, entry); err != nil {
			slog.Error("Background refresh cache set failed", "domain", domain, "type", qtype, "error", err)
		}
		call.entry = entry
	} else {
		slog.Error("Background refresh failed", "domain", domain, "type", qtype, "error", err)
		call.err = err
	}
	call.once.Do(func() { close(call.done) })
	inflightMu.Lock()
	delete(inflightCalls, ikey)
	inflightMu.Unlock()
}

func resolve(ctx context.Context, domain string, qtype uint16, group *upstream.Group, c cache.Cache, maxPayload uint16, network string, runtimeCfg *config.RuntimeConfig, do bool, m *metrics.Metrics, ecsData []byte, preferredUpstream string) (*cache.Entry, string, error) {
	m.CacheLookups.Inc()
	m.NegativeCacheLookups.Inc()
	ttlMin := int(runtimeCfg.TTLMin.Load())
	ttlMax := int(runtimeCfg.TTLMax.Load())
	negativeTTL := int(runtimeCfg.NegativeTTL.Load())

	entry, found := c.Peek(ctx, domain, qtype)
	if found {
		if !entry.Expired() {
			slog.Debug("Cache hit", "domain", domain, "type", qtype)
			m.CacheHits.Inc()
			if entry.RCode == 3 || (entry.RCode == 0 && len(entry.Answers) == 0) {
				m.NegativeCacheHits.Inc()
			}
			entry.RecordHit()
			return entry, "", nil
		}
		if staleAge := int(runtimeCfg.StaleAge.Load()); staleAge > 0 {
			expiredFor := time.Since(entry.ExpiresAt)
			if expiredFor < time.Duration(staleAge)*time.Second {
				slog.Info("Serving stale entry, refreshing in background", "domain", domain, "type", qtype)
				ikey := inflightKey{domain, qtype}
				inflightMu.Lock()
				if _, exists := inflightCalls[ikey]; !exists {
					call := &inflightCall{done: make(chan struct{})}
					inflightCalls[ikey] = call
					inflightMu.Unlock()

					staleLockKey := fmt.Sprintf("northstar:inflight:stale:%s:%d", domain, qtype)
					locked, lErr := c.TryLock(ctx, staleLockKey, 5*time.Second)
					if lErr == nil && locked {
						go refreshCache(call, ikey, domain, qtype, c, maxPayload, network, group, do, m, ttlMin, ttlMax, negativeTTL, ecsData)
					} else {
						if lErr != nil {
							slog.Error("Stale refresh lock error", "error", lErr)
						}
						inflightMu.Lock()
						delete(inflightCalls, ikey)
						inflightMu.Unlock()
						call.once.Do(func() { close(call.done) })
					}
				} else {
					inflightMu.Unlock()
				}
				return entry, "", nil
			}
		}
	}

	lockKey := fmt.Sprintf("northstar:inflight:%s:%d", domain, qtype)
	usingDistributedLock := false

	ikey := inflightKey{domain, qtype}
	inflightMu.Lock()
	if call, ok := inflightCalls[ikey]; ok {
		inflightMu.Unlock()
		slog.Debug("Waiting for in-flight fetch", "domain", domain, "type", qtype)
		select {
		case <-call.done:
			if call.entry != nil {
				return call.entry, "", nil
			}
			if call.err != nil {
				return nil, "", call.err
			}
			return nil, "", fmt.Errorf("inflight fetch failed")
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	call := &inflightCall{done: make(chan struct{})}
	inflightCalls[ikey] = call
	inflightMu.Unlock()

	defer func() {
		call.once.Do(func() { close(call.done) })
		if usingDistributedLock {
			if err := c.Unlock(ctx, lockKey); err != nil {
				slog.Error("Failed to release distributed lock", "key", lockKey, "error", err)
			}
		}
		inflightMu.Lock()
		delete(inflightCalls, ikey)
		inflightMu.Unlock()
	}()

	locked, err := c.TryLock(ctx, lockKey, 10*time.Second)
	if err != nil {
		slog.Error("Distributed lock error, falling back to direct fetch", "key", lockKey, "error", err)
	} else if !locked {
		slog.Debug("Another node is fetching, polling cache", "domain", domain, "type", qtype)
		pollStart := time.Now()
		for time.Since(pollStart) < 5*time.Second {
			select {
			case <-ctx.Done():
				return nil, "", ctx.Err()
			default:
			}
			time.Sleep(50 * time.Millisecond)
			if entry, found := c.Peek(ctx, domain, qtype); found && !entry.Expired() {
				slog.Debug("Poll succeeded, another node cached the entry", "domain", domain, "type", qtype)
				m.CacheHits.Inc()
				entry.RecordHit()
				call.entry = entry
				return entry, "", nil
			}
		}
		slog.Debug("Poll timed out, fetching directly", "domain", domain, "type", qtype)
	} else {
		usingDistributedLock = true
	}

	var selectedUpstreams []*upstream.Upstream
	if preferredUpstream != "" {
		if u := group.GetByName(preferredUpstream); u != nil && u.IsHealthy() {
			selectedUpstreams = []*upstream.Upstream{u}
		}
	}
	if len(selectedUpstreams) == 0 {
		selectedUpstreams = group.SelectN(ctx, domain, group.Concurrency)
	}
	if len(selectedUpstreams) == 0 {
		err = fmt.Errorf("no healthy upstream available")
		call.err = err
		return nil, "", err
	}

	var upstreamName string
	if len(selectedUpstreams) == 1 {
		u := selectedUpstreams[0]
		entry, err = fetchFromUpstream(ctx, domain, qtype, maxPayload, network, u, do, m, ttlMin, ttlMax, negativeTTL, ecsData)
		if err != nil {
			u.ReportFailure()
			m.UpstreamFails.WithLabelValues(u.Name).Inc()
			call.err = err
			return nil, "", err
		}
		upstreamName = u.Name
	} else {
		entry, upstreamName, err = raceUpstreams(ctx, domain, qtype, maxPayload, network, selectedUpstreams, group, do, m, ttlMin, ttlMax, negativeTTL, ecsData)
		if err != nil {
			call.err = err
			return nil, "", err
		}
	}
	if err := c.Set(ctx, entry); err != nil {
		slog.Error("Cache set failed", "domain", domain, "type", qtype, "error", err)
	}
	call.entry = entry
	return entry, upstreamName, nil
}

func raceUpstreams(ctx context.Context, domain string, qtype uint16, maxPayload uint16, network string, upstreams []*upstream.Upstream, group *upstream.Group, do bool, m *metrics.Metrics, ttlMin, ttlMax, negativeTTL int, ecsData []byte) (*cache.Entry, string, error) {
	type raceResult struct {
		entry *cache.Entry
		name  string
		err   error
	}
	resultCh := make(chan raceResult, len(upstreams))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, u := range upstreams {
		u := u
		go func() {
			entry, err := fetchFromUpstream(raceCtx, domain, qtype, maxPayload, network, u, do, m, ttlMin, ttlMax, negativeTTL, ecsData)
			select {
			case resultCh <- raceResult{entry, u.Name, err}:
			case <-raceCtx.Done():
			}
		}()
	}

	var lastErr error
	for range upstreams {
		select {
		case res := <-resultCh:
			if res.err == nil {
				cancel()
				return res.entry, res.name, nil
			}
			lastErr = res.err
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	return nil, "", lastErr
}
