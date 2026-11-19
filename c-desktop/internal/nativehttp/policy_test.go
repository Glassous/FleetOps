package nativehttp

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func request(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func configured(t *testing.T, origins ...string) *Connections {
	t.Helper()
	c := New()
	if err := c.SetTargets(origins); err != nil {
		t.Fatal(err)
	}
	return c
}

func testClient(t *testing.T, c *Connections) *http.Client {
	t.Helper()
	client := Client(c)
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestPublicMethods(t *testing.T) {
	typ := reflect.TypeOf(New())
	if typ.NumMethod() != 1 || typ.Method(0).Name != "SetTargets" {
		t.Fatalf("IPC-visible methods must contain only SetTargets: %v", typ)
	}
}

func TestOriginNormalization(t *testing.T) {
	cases := []struct {
		origin string
		target string
	}{
		{"HTTP://EXAMPLE.COM:80/", "http://example.com/api/v1/status"},
		{"http://example.com", "http://EXAMPLE.COM:080/api/v1/status"},
		{"https://EXAMPLE.COM:443", "https://example.com/api/v1/status"},
		{"https://example.com/", "https://EXAMPLE.COM:443/api/v1/status"},
		{"http://127.0.0.1:80", "http://127.0.0.1/api/v1/status"},
		{"http://LOCALHOST:80", "http://localhost/api/v1/status"},
		{"http://[0:0:0:0:0:0:0:1]:80/", "http://[::1]/api/v1/status"},
		{"https://[::1]", "https://[0:0:0:0:0:0:0:1]:443/api/v1/status"},
		{"http://[2001:DB8::A]:08080", "http://[2001:db8:0:0:0:0:0:a]:8080/api/v1/status"},
		{"http://localhost:1", "http://localhost:1/api/v1/status"},
		{"http://localhost:65535", "http://localhost:65535/api/v1/status"},
	}
	for _, tc := range cases {
		t.Run(tc.origin, func(t *testing.T) {
			c := configured(t, tc.origin)
			if !Allow(c, request(t, http.MethodGet, tc.target, nil)) {
				t.Fatalf("%q did not authorize %q", tc.origin, tc.target)
			}
		})
	}
}

func TestSetTargetsAtomicity(t *testing.T) {
	invalid := []string{
		"", "example.com", "//example.com", "ftp://example.com", "http:example.com", "http:///",
		"http://user@example.com", "http://user:password@example.com", "http://example.com/path",
		"http://example.com//", "http://example.com/%2f", "http://example.com?x=1",
		"http://example.com?", "http://example.com#fragment", "http://example.com#",
		"http://", "http://:80", "http://example.com:", "http://example.com:0",
		"http://example.com:-1", "http://example.com:+80", "http://example.com:65536",
		"http://example.com:9999999999999999999999999", "http://example.com:http",
		"http://[::1]:", "http://[::1]:0", "http://[::1]:65536", "http://::1",
		"http://[localhost]", "http://[127.0.0.1]", "http://[fe80::1%25eth0]",
		"http://bad host", "http://-bad.example", "http://bad..example",
	}
	for _, origin := range invalid {
		t.Run(origin, func(t *testing.T) {
			c := configured(t, "https://old.example")
			if err := c.SetTargets([]string{"https://new.example", origin}); err == nil {
				t.Fatalf("accepted invalid origin %q", origin)
			}
			if !Allow(c, request(t, http.MethodGet, "https://old.example/api/v1/status", nil)) {
				t.Fatal("invalid update removed the previous targets")
			}
			if Allow(c, request(t, http.MethodGet, "https://new.example/api/v1/status", nil)) {
				t.Fatal("invalid update partially installed new targets")
			}
		})
	}
	var c Connections
	if err := c.SetTargets([]string{"https://old.example", "https://OLD.example:443"}); err != nil {
		t.Fatal(err)
	}
	if len(c.targets) != 1 {
		t.Fatal("normalized duplicate origins were not deduplicated")
	}
	if err := c.SetTargets([]string{"https://new.example"}); err != nil {
		t.Fatal(err)
	}
	if Allow(&c, request(t, http.MethodGet, "https://old.example/api/v1/status", nil)) {
		t.Fatal("SetTargets appended instead of replacing")
	}
	if err := c.SetTargets(nil); err != nil {
		t.Fatal(err)
	}
	if Allow(&c, request(t, http.MethodGet, "https://new.example/api/v1/status", nil)) {
		t.Fatal("deleted target remains allowed")
	}
}

func TestAllowedRequests(t *testing.T) {
	c := configured(t, "https://fleet.example")
	cases := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/session"},
		{http.MethodGet, "/api/v1/session"},
		{http.MethodDelete, "/api/v1/session"},
		{http.MethodGet, "/api/v1/status"},
		{http.MethodGet, "/api/v1/monitor"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodGet, "/api/v1/events?limit=1"},
		{http.MethodGet, "/api/v1/events?limit=100&before=1"},
		{http.MethodGet, "/api/v1/events?before=999999999999999999999999999999"},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := request(t, tc.method, "https://fleet.example"+tc.path, nil)
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Authorization", "Bearer test-token")
			r.Header.Set("Content-Type", "application/json")
			if !Allow(c, r) {
				t.Fatal("valid request was denied")
			}
			r.Header.Set("Content-Type", "")
			if !Allow(c, r) {
				t.Fatal("empty content type was denied")
			}
			r.Host = ""
			if !Allow(c, r) {
				t.Fatal("URL-derived Host was denied")
			}
		})
	}
}

func TestDeniedRequests(t *testing.T) {
	c := configured(t, "https://fleet.example")
	cases := []struct{ method, target string }{
		{http.MethodGet, "https://other.example/api/v1/status"},
		{http.MethodGet, "http://fleet.example/api/v1/status"},
		{http.MethodGet, "https://fleet.example:444/api/v1/status"},
		{http.MethodGet, "https://user:pass@fleet.example/api/v1/status"},
		{http.MethodGet, "https://fleet.example/api/v1/status#fragment"},
		{http.MethodGet, "https://fleet.example/"},
		{http.MethodGet, "https://fleet.example/api/v1/status/"},
		{http.MethodGet, "https://fleet.example/api/v1/status/../session"},
		{http.MethodGet, "https://fleet.example/api/v1/%73tatus"},
		{http.MethodGet, "https://fleet.example/api%2fv1/status"},
		{http.MethodHead, "https://fleet.example/api/v1/status"},
		{http.MethodPost, "https://fleet.example/api/v1/status"},
		{http.MethodPut, "https://fleet.example/api/v1/session"},
		{http.MethodPatch, "https://fleet.example/api/v1/session"},
		{http.MethodOptions, "https://fleet.example/api/v1/session"},
		{http.MethodPost, "https://fleet.example/api/v1/monitor"},
		{http.MethodDelete, "https://fleet.example/api/v1/events"},
		{"get", "https://fleet.example/api/v1/events"},
	}
	for _, tc := range cases {
		t.Run(tc.method+tc.target, func(t *testing.T) {
			if Allow(c, request(t, tc.method, tc.target, nil)) {
				t.Fatal("unauthorized request was allowed")
			}
		})
	}
	if Allow(c, nil) || Allow(c, &http.Request{}) || Allow(nil, request(t, "GET", "https://fleet.example/api/v1/status", nil)) {
		t.Fatal("nil policy or request was allowed")
	}
	if Allow(New(), request(t, "GET", "https://fleet.example/api/v1/status", nil)) {
		t.Fatal("new policy did not deny by default")
	}
}

func TestDeniedHeadersAndHost(t *testing.T) {
	c := configured(t, "https://fleet.example")
	for _, name := range []string{"Host", "hOsT", "Cookie", "Origin", "Referer", "User-Agent", "Accept-Encoding", "Content-Length", "Connection", "X-FleetOps"} {
		t.Run(name, func(t *testing.T) {
			r := request(t, "GET", "https://fleet.example/api/v1/status", nil)
			r.Header[name] = []string{"test"}
			if Allow(c, r) {
				t.Fatalf("forbidden header %s was allowed", name)
			}
		})
	}
	mutations := map[string]func(*http.Request){
		"host override":       func(r *http.Request) { r.Host = "other.example" },
		"host port override":  func(r *http.Request) { r.Host = "fleet.example:444" },
		"non JSON":            func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"JSON with parameter": func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") },
		"duplicate type":      func(r *http.Request) { r.Header["Content-Type"] = []string{"application/json", "application/json"} },
		"case duplicate type": func(r *http.Request) {
			r.Header["Content-Type"] = []string{"application/json"}
			r.Header["content-type"] = []string{"application/json"}
		},
		"header injection": func(r *http.Request) { r.Header.Set("Accept", "application/json\r\nHost: other.example") },
		"trailer":          func(r *http.Request) { r.Trailer = http.Header{"Authorization": []string{"test"}} },
		"transfer encoding": func(r *http.Request) {
			r.TransferEncoding = []string{"chunked"}
		},
		"request URI": func(r *http.Request) { r.RequestURI = "/api/v1/status" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := request(t, "GET", "https://fleet.example/api/v1/status", nil)
			mutate(r)
			if Allow(c, r) {
				t.Fatal("forbidden request field was allowed")
			}
		})
	}
}

func TestDeniedQueries(t *testing.T) {
	c := configured(t, "https://fleet.example")
	paths := []string{
		"/api/v1/session?limit=1", "/api/v1/status?limit=1", "/api/v1/monitor?before=1", "/api/v1/status?",
		"/api/v1/events?", "/api/v1/events?limit=0", "/api/v1/events?limit=101", "/api/v1/events?limit=-1", "/api/v1/events?limit=1.5",
		"/api/v1/events?limit=", "/api/v1/events?limit", "/api/v1/events?limit=1&limit=2", "/api/v1/events?limit=1&%6cimit=2",
		"/api/v1/events?before=0", "/api/v1/events?before=000", "/api/v1/events?before=-1", "/api/v1/events?before=1.5",
		"/api/v1/events?before=", "/api/v1/events?before=1&before=2", "/api/v1/events?before=%2B1", "/api/v1/events?before=+1",
		"/api/v1/events?extra=1", "/api/v1/events?LIMIT=1", "/api/v1/events?limit=1;before=2", "/api/v1/events?limit=%zz",
		"/api/v1/events?limit=1&", "/api/v1/events?&before=1", "/api/v1/events?limit=1&&before=2",
		"/api/v1/events?limit=9999999999999999999999999999",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if Allow(c, request(t, "GET", "https://fleet.example"+path, nil)) {
				t.Fatal("forbidden query was allowed")
			}
		})
	}
}

func TestConcurrentTargets(t *testing.T) {
	c := configured(t, "http://localhost")
	r := request(t, "GET", "http://localhost/api/v1/status", nil)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if i%2 == 0 {
					targets := []string{"http://localhost"}
					if j%2 == 0 {
						targets = nil
					}
					if err := c.SetTargets(targets); err != nil {
						t.Error(err)
					}
				} else {
					Allow(c, r)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestStatusAndRevocation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/v1/status" {
			t.Error("unexpected request")
		}
		if r.Header.Get("User-Agent") != "" || r.Header.Get("Accept-Encoding") != "" {
			t.Error("transport added unwanted optional headers")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	c := configured(t, server.URL)
	client := testClient(t, c)
	if client.Timeout != 8*time.Second {
		t.Fatalf("unexpected timeout: %v", client.Timeout)
	}
	r := request(t, "GET", server.URL+"/api/v1/status", nil)
	r.Header = nil
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(data) != `{"status":"ok"}` || response.StatusCode != http.StatusOK {
		t.Fatalf("response: %s, status %d, error %v", data, response.StatusCode, err)
	}
	if r.Header != nil {
		t.Fatal("transport mutated the caller's request headers")
	}
	if err := c.SetTargets(nil); err != nil {
		t.Fatal(err)
	}
	if Allow(c, r) {
		t.Fatal("revoked target is still allowed")
	}
	if _, err := client.Do(r); !errors.Is(err, errDenied) {
		t.Fatalf("transport did not recheck the policy: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("revoked request reached the server")
	}
}

func TestClientCannotBypassAllow(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	c := configured(t, server.URL)
	client := testClient(t, c)
	mutations := map[string]func(*http.Request){
		"origin": func(r *http.Request) { r.URL.Host = "127.0.0.1:1"; r.Host = r.URL.Host },
		"path":   func(r *http.Request) { r.URL.Path = "/not-allowed" },
		"method": func(r *http.Request) { r.Method = http.MethodPatch },
		"header": func(r *http.Request) { r.Header.Set("Cookie", "test") },
		"host":   func(r *http.Request) { r.Host = "other.example" },
		"query":  func(r *http.Request) { r.URL.RawQuery = "limit=1" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			body := &trackedBody{reader: strings.NewReader("{}")}
			r := request(t, "GET", server.URL+"/api/v1/status", body)
			mutate(r)
			if _, err := client.Do(r); !errors.Is(err, errDenied) {
				t.Fatalf("client did not enforce Allow: %v", err)
			}
			if body.closes.Load() != 1 {
				t.Fatal("rejected request body was not closed")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("forbidden requests reached the server")
	}
}

func TestRedirectsDenied(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var redirected atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/monitor" {
					redirected.Add(1)
					return
				}
				http.Redirect(w, r, "/api/v1/monitor", code)
			}))
			defer server.Close()
			client := testClient(t, configured(t, server.URL))
			response, err := client.Get(server.URL + "/api/v1/status")
			if response != nil {
				response.Body.Close()
			}
			if !errors.Is(err, errRedirect) {
				t.Fatalf("redirect must fail rather than return a normal response: %v", err)
			}
			if redirected.Load() != 0 {
				t.Fatal("client followed a redirect")
			}
		})
	}
}

func TestResponseLimits(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		for _, size := range []int64{0, responseLimit, responseLimit + 1} {
			name := strconv.FormatBool(unknown) + "/" + strconv.FormatInt(size, 10)
			t.Run(name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if unknown {
						w.(http.Flusher).Flush()
					} else {
						w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
					}
					io.WriteString(w, strings.Repeat("x", int(size)))
				}))
				defer server.Close()
				client := testClient(t, configured(t, server.URL))
				response, err := client.Get(server.URL + "/api/v1/status")
				if size > responseLimit && !unknown {
					if !errors.Is(err, errResponseTooLarge) {
						t.Fatalf("known oversized response: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if unknown && response.ContentLength != -1 {
					t.Fatal("fixture did not produce an unknown-length response")
				}
				data, err := io.ReadAll(response.Body)
				if size > responseLimit {
					if !errors.Is(err, errResponseTooLarge) || len(data) != int(responseLimit) {
						t.Fatalf("oversized streamed response returned %d bytes, error %v", len(data), err)
					}
				} else if err != nil || len(data) != int(size) {
					t.Fatalf("valid response returned %d bytes, error %v", len(data), err)
				}
			})
		}
	}
}

func TestRequestLimits(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		for _, size := range []int64{0, requestLimit, requestLimit + 1} {
			name := strconv.FormatBool(unknown) + "/" + strconv.FormatInt(size, 10)
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil || n != size || n > requestLimit {
						t.Errorf("server received %d bytes, error %v", n, err)
					}
					io.WriteString(w, "ok")
				}))
				defer server.Close()
				body := &trackedBody{reader: strings.NewReader(strings.Repeat("x", int(size)))}
				r := request(t, "POST", server.URL+"/api/v1/session", body)
				r.ContentLength = size
				if unknown {
					r.ContentLength = -1
				}
				r.Header.Set("Content-Type", "application/json")
				client := testClient(t, configured(t, server.URL))
				response, err := client.Do(r)
				if response != nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				if size > requestLimit {
					if !errors.Is(err, errRequestTooLarge) || calls.Load() != 0 {
						t.Fatalf("oversized request: calls %d, error %v", calls.Load(), err)
					}
				} else if err != nil || calls.Load() != 1 {
					t.Fatalf("valid request: calls %d, error %v", calls.Load(), err)
				}
				if body.closes.Load() != 1 || body.bytesRead.Load() > requestLimit+1 {
					t.Fatalf("request body closes %d, bytes read %d", body.closes.Load(), body.bytesRead.Load())
				}
			})
		}
	}
}

func TestRevocationDuringRequestRead(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	c := configured(t, server.URL)
	body := &trackedBody{reader: strings.NewReader("{}"), onRead: func() {
		if err := c.SetTargets(nil); err != nil {
			t.Error(err)
		}
	}}
	r := request(t, "POST", server.URL+"/api/v1/session", body)
	if _, err := testClient(t, c).Do(r); !errors.Is(err, errDenied) {
		t.Fatalf("policy was not checked after buffering: %v", err)
	}
	if calls.Load() != 0 || body.closes.Load() != 1 {
		t.Fatal("revoked request was sent or its body was left open")
	}
}

func TestUntrustedTLSCertificate(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	client := testClient(t, configured(t, server.URL))
	_, err := client.Get(server.URL + "/api/v1/status")
	var authorityErr x509.UnknownAuthorityError
	if !errors.As(err, &authorityErr) {
		t.Fatalf("expected an untrusted certificate error, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("TLS verification was bypassed")
	}
}

func TestResponseCancellation(t *testing.T) {
	serverDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(serverDone)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := request(t, "GET", server.URL+"/api/v1/status", nil).WithContext(ctx)
	client := testClient(t, configured(t, server.URL))
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	result := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(response.Body)
		result <- err
	}()
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled read returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("response read ignored cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("server connection remained open after cancellation")
	}
}

func TestRequestReadCancellation(t *testing.T) {
	body := &blockingBody{started: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := configured(t, "http://127.0.0.1:1")
	r := request(t, "POST", "http://127.0.0.1:1/api/v1/session", body).WithContext(ctx)
	client := testClient(t, c)
	result := make(chan error, 1)
	go func() {
		_, err := client.Do(r)
		result <- err
	}()
	select {
	case <-body.started:
	case <-time.After(3 * time.Second):
		t.Fatal("request body was not read")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled request returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request body read ignored cancellation")
	}
}

func TestLimitedBodyClosesAndReportsOverflow(t *testing.T) {
	for _, size := range []int{0, 4, 5, 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			original := &trackedBody{reader: strings.NewReader(strings.Repeat("x", size))}
			body := newLimitedBody(original, 4, errResponseTooLarge)
			data, err := io.ReadAll(body)
			if size > 4 {
				if !errors.Is(err, errResponseTooLarge) || len(data) != 4 {
					t.Fatalf("overflow returned %d bytes, error %v", len(data), err)
				}
				if _, err := body.Read(make([]byte, 1)); !errors.Is(err, errResponseTooLarge) {
					t.Fatalf("overflow became EOF on subsequent read: %v", err)
				}
			} else if err != nil || len(data) != size {
				t.Fatalf("valid body returned %d bytes, error %v", len(data), err)
			}
			if original.closes.Load() != 1 || original.bytesRead.Load() > 5 {
				t.Fatal("body was not closed promptly or read beyond the overflow probe")
			}
			body.Close()
			if original.closes.Load() != 1 {
				t.Fatal("body was closed more than once")
			}
		})
	}
}

type trackedBody struct {
	reader    io.Reader
	onRead    func()
	readOnce  sync.Once
	closes    atomic.Int32
	bytesRead atomic.Int64
}

func (b *trackedBody) Read(p []byte) (int, error) {
	b.readOnce.Do(func() {
		if b.onRead != nil {
			b.onRead()
		}
	})
	n, err := b.reader.Read(p)
	b.bytesRead.Add(int64(n))
	return n, err
}

func (b *trackedBody) Close() error {
	b.closes.Add(1)
	return nil
}

type blockingBody struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func (b *blockingBody) Read([]byte) (int, error) {
	b.startOnce.Do(func() { close(b.started) })
	<-b.closed
	return 0, context.Canceled
}

func (b *blockingBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}
