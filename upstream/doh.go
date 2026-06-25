package upstream

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/bata94/northstar/dns"
)

type DoHClient struct {
	client  *http.Client
	url     string
	timeout time.Duration
}

func NewDoHClient(url string, timeout int) *DoHClient {
	return &DoHClient{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:       10,
				IdleConnTimeout:    30 * time.Second,
				DisableCompression: true,
			},
		},
		url:     url,
		timeout: time.Duration(timeout) * time.Second,
	}
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
