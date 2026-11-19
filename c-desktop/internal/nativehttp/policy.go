package nativehttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	requestLimit  int64 = 32 << 10
	responseLimit int64 = 1 << 20
	clientTimeout       = 8 * time.Second
)

var (
	errDenied           = errors.New("nativehttp: request is not allowed")
	errRequestTooLarge  = errors.New("nativehttp: request body exceeds 32 KiB")
	errResponseTooLarge = errors.New("nativehttp: response body exceeds 1 MiB")
	errRedirect         = errors.New("nativehttp: redirects are not allowed")
)

type Connections struct {
	mu      sync.RWMutex
	targets map[string]struct{}
}

func New() *Connections {
	return &Connections{targets: make(map[string]struct{})}
}

func (c *Connections) SetTargets(origins []string) error {
	targets := make(map[string]struct{}, len(origins))
	for i, raw := range origins {
		u, err := url.Parse(raw)
		if err != nil || strings.ContainsAny(raw, "?#") || u == nil ||
			(u.Path != "" && u.Path != "/") || (u.RawPath != "" && u.RawPath != u.Path) {
			return fmt.Errorf("nativehttp: target %d is not an origin", i)
		}
		origin, err := normalizeOrigin(u)
		if err != nil {
			return fmt.Errorf("nativehttp: target %d: %w", i, err)
		}
		targets[origin] = struct{}{}
	}
	c.mu.Lock()
	c.targets = targets
	c.mu.Unlock()
	return nil
}

func Client(c *Connections) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        8,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  clientTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableCompression:     true,
	}
	return &http.Client{
		Transport: &policyTransport{connections: c, transport: transport},
		Timeout:   clientTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

func Allow(c *Connections, r *http.Request) bool {
	if c == nil || r == nil || r.URL == nil || r.RequestURI != "" ||
		(r.Host != "" && r.Host != r.URL.Host) || len(r.Trailer) != 0 || len(r.TransferEncoding) != 0 {
		return false
	}
	origin, err := normalizeOrigin(r.URL)
	if err != nil {
		return false
	}
	c.mu.RLock()
	_, allowed := c.targets[origin]
	c.mu.RUnlock()
	if !allowed || (r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path) {
		return false
	}

	switch r.URL.Path {
	case "/api/v1/session":
		if r.Method != http.MethodPost && r.Method != http.MethodGet && r.Method != http.MethodDelete {
			return false
		}
	case "/api/v1/status", "/api/v1/monitor", "/api/v1/events":
		if r.Method != http.MethodGet {
			return false
		}
	default:
		return false
	}
	if r.URL.Path == "/api/v1/events" {
		if !validEventsQuery(r.URL) {
			return false
		}
	} else if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return false
	}

	contentTypes := 0
	for name, values := range r.Header {
		switch strings.ToLower(name) {
		case "accept", "authorization":
		case "content-type":
			contentTypes += len(values)
			if contentTypes > 1 {
				return false
			}
			for _, value := range values {
				if value != "" && !strings.EqualFold(value, "application/json") {
					return false
				}
			}
		default:
			return false
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return false
			}
		}
	}
	return true
}

func normalizeOrigin(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Opaque != "" || u.User != nil ||
		u.Fragment != "" || u.RawFragment != "" || u.Host == "" || u.OmitHost {
		return "", errors.New("invalid HTTP origin")
	}
	hostname := u.Hostname()
	host := strings.ToLower(hostname)
	addr, addrErr := netip.ParseAddr(host)
	bracketed := strings.HasPrefix(u.Host, "[")
	authority := hostname
	if bracketed {
		if addrErr != nil || !addr.Is6() || addr.Zone() != "" {
			return "", errors.New("invalid IPv6 host")
		}
		authority = "[" + hostname + "]"
		host = "[" + addr.String() + "]"
	} else if addrErr == nil {
		if !addr.Is4() {
			return "", errors.New("IPv6 host requires brackets")
		}
		host = addr.String()
	} else if !validHostname(host) {
		return "", errors.New("invalid host")
	}

	port := u.Port()
	if u.Host != authority {
		if port == "" || u.Host != authority+":"+port || !positiveDecimal(port) {
			return "", errors.New("invalid port")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n > 65535 {
			return "", errors.New("invalid port")
		}
		if !((scheme == "http" && n == 80) || (scheme == "https" && n == 443)) {
			host += ":" + strconv.Itoa(n)
		}
	}
	return scheme + "://" + host, nil
}

func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}

func validEventsQuery(u *url.URL) bool {
	if u.RawQuery == "" {
		return !u.ForceQuery
	}
	for _, part := range strings.Split(u.RawQuery, "&") {
		if part == "" {
			return false
		}
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if len(values) != 1 || !positiveDecimal(values[0]) {
			return false
		}
		switch key {
		case "limit":
			n, err := strconv.Atoi(values[0])
			if err != nil || n > 100 {
				return false
			}
		case "before":
		default:
			return false
		}
	}
	return true
}

func positiveDecimal(value string) bool {
	positive := false
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
		positive = positive || ch != '0'
	}
	return positive
}

type policyTransport struct {
	connections *Connections
	transport   *http.Transport
}

func (t *policyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !Allow(t.connections, r) {
		if r != nil && r.Body != nil {
			r.Body.Close()
		}
		return nil, errDenied
	}
	if r.ContentLength > requestLimit {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, errRequestTooLarge
	}
	req := r.Clone(r.Context())
	if r.Body != nil && r.Body != http.NoBody {
		body := newLimitedBody(r.Body, requestLimit, errRequestTooLarge)
		stop := context.AfterFunc(r.Context(), func() { body.Close() })
		data, err := io.ReadAll(body)
		stop()
		body.Close()
		if ctxErr := r.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.ContentLength = int64(len(data))
		if len(data) == 0 {
			req.Body = http.NoBody
		}
	}
	req.GetBody = nil
	if !Allow(t.connections, req) {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errDenied
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("User-Agent", "")
	response, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > responseLimit {
		response.Body.Close()
		return nil, errResponseTooLarge
	}
	response.Body = newLimitedBody(response.Body, responseLimit, errResponseTooLarge)
	return response, nil
}

func (t *policyTransport) CloseIdleConnections() {
	t.transport.CloseIdleConnections()
}

type limitedBody struct {
	body      io.ReadCloser
	remaining int64
	limitErr  error
	terminal  error
	closeOnce sync.Once
	closeErr  error
}

func newLimitedBody(body io.ReadCloser, limit int64, limitErr error) *limitedBody {
	return &limitedBody{body: body, remaining: limit, limitErr: limitErr}
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.terminal != nil {
		return 0, b.terminal
	}
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.body.Read(extra[:])
		if n > 0 {
			err = b.limitErr
		}
		if err != nil {
			b.terminal = err
			b.Close()
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	if err != nil {
		b.terminal = err
		b.Close()
	}
	return n, err
}

func (b *limitedBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.body.Close() })
	return b.closeErr
}
