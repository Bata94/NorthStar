package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/bata94/northstar/dns"
	"golang.org/x/net/http2"
)

type DoHClient struct {
	client  *http.Client
	url     string
	timeout time.Duration
	origin  string

	mu                  sync.Mutex
	lastNegotiatedProto string
}

type DoHOptions struct {
	URL                 string
	Timeout             int
	ProxyAddress        string
	ProxyAuth           string
	HTTP2Enabled        bool
	MaxIdleConnsPerHost int
	TLSConfig           *tls.Config // optional TLS config for the transport
}

func NewDoHClient(opts DoHOptions) *DoHClient {
	var transport *http.Transport
	if opts.HTTP2Enabled {
		transport = getOrCreateDoHTransport(opts)
	} else {
		transport = newDoHTransport(opts)
	}

	origin := extractOrigin(opts.URL)

	return &DoHClient{
		client: &http.Client{
			Timeout:   time.Duration(opts.Timeout) * time.Second,
			Transport: transport,
		},
		url:     opts.URL,
		timeout: time.Duration(opts.Timeout) * time.Second,
		origin:  origin,
	}
}

func extractOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// LastNegotiatedProtocol returns the most recently negotiated HTTP protocol version.
func (d *DoHClient) LastNegotiatedProtocol() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastNegotiatedProto
}

func (d *DoHClient) recordNegotiatedProtocol(resp *http.Response) {
	if resp == nil || resp.TLS == nil {
		return
	}
	d.mu.Lock()
	d.lastNegotiatedProto = resp.TLS.NegotiatedProtocol
	d.mu.Unlock()
}

func (d *DoHClient) Query(ctx context.Context, msg *dns.Message) (*dns.Message, error) {
	packed := msg.Pack()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	d.recordNegotiatedProtocol(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var reply dns.Message
	if err := reply.Parse(body); err != nil {
		return nil, err
	}

	return &reply, nil
}

// Transport returns the underlying http.Transport for inspection.
func (d *DoHClient) Transport() *http.Transport {
	if t, ok := d.client.Transport.(*http.Transport); ok {
		return t
	}
	return nil
}

// Client returns the underlying http.Client for transport sharing.
func (d *DoHClient) Client() *http.Client {
	return d.client
}

// Origin returns the scheme://host portion of the DoH URL.
func (d *DoHClient) Origin() string {
	return d.origin
}

// SetTransport replaces the http.Client transport (used for transport sharing).
func (d *DoHClient) SetTransport(transport *http.Transport) {
	d.client.Transport = transport
}

var (
	// dohTransports maps origin -> *http.Transport for same-origin coalescing.
	dohTransports syncMap
)

type syncMap struct {
	mu sync.RWMutex
	m  map[string]*sharedTransport
}

type sharedTransport struct {
	transport *http.Transport
	refCount  int
}

func getOrCreateDoHTransport(opts DoHOptions) *http.Transport {
	if !opts.HTTP2Enabled {
		// No HTTP/2 enabled, create a plain transport with proxy support
		return newDoHTransport(opts)
	}

	origin := extractOrigin(opts.URL)
	if origin == "" {
		return newDoHTransport(opts)
	}

	dohTransports.mu.Lock()
	defer dohTransports.mu.Unlock()

	if dohTransports.m == nil {
		dohTransports.m = make(map[string]*sharedTransport)
	}

	if st, ok := dohTransports.m[origin]; ok {
		st.refCount++
		return st.transport
	}

	transport := newDoHTransport(opts)
	dohTransports.m[origin] = &sharedTransport{
		transport: transport,
		refCount:  1,
	}
	return transport
}

func releaseDoHTransport(origin string) {
	dohTransports.mu.Lock()
	defer dohTransports.mu.Unlock()

	if dohTransports.m == nil {
		return
	}

	st, ok := dohTransports.m[origin]
	if !ok {
		return
	}
	st.refCount--
	if st.refCount <= 0 {
		st.transport.CloseIdleConnections()
		delete(dohTransports.m, origin)
	}
}

func newDoHTransport(opts DoHOptions) *http.Transport {
	maxIdle := opts.MaxIdleConnsPerHost
	if maxIdle < 2 {
		maxIdle = 10
	}

	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: maxIdle,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   opts.HTTP2Enabled,
		TLSClientConfig:     opts.TLSConfig,
	}

	if opts.ProxyAddress != "" {
		proxyURL, err := url.Parse(opts.ProxyAddress)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			if opts.ProxyAuth != "" {
				encoded := base64.StdEncoding.EncodeToString([]byte(opts.ProxyAuth))
				transport.ProxyConnectHeader = http.Header{
					"Proxy-Authorization": []string{"Basic " + encoded},
				}
			}
		}
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}

	if opts.HTTP2Enabled {
		_ = http2.ConfigureTransport(transport)
	}

	return transport
}

// CloseIdleConnections closes idle connections on the shared transport.
func (d *DoHClient) CloseIdleConnections() {
	if transport := d.Transport(); transport != nil {
		transport.CloseIdleConnections()
	}
}
