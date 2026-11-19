package poller

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fleetops/b-monitor/internal/config"
	"fleetops/b-monitor/internal/store"
)

const validStatus = `{"apiVersion":"1","nodeId":"node-a","hostname":"test-host","system":{"os":"linux","platform":"test","kernel":"6","arch":"amd64"},"agentVersion":"test","metricsScope":"host","sampledAt":"2020-01-01T00:00:00Z","agentStartedAt":"2019-01-01T00:00:00Z","uptimeSeconds":10,"cpu":{"logicalCount":2,"usagePercent":null},"memory":null,"disk":{"totalBytes":100,"usedBytes":20,"usedPercent":20}}`

func testPoller(t *testing.T, url string) (*Poller, *store.Store) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c := config.Defaults()
	c.PollIntervalSeconds = 1
	c.TimeoutSeconds = 1
	p, err := New(c, []config.Target{{ID: "a", Name: "Agent A", URL: url, ExpectedNodeID: "node-a", Token: "machine-secret"}}, s, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.client.CloseIdleConnections)
	return p, s
}

func events(t *testing.T, s *store.Store) []store.Event {
	t.Helper()
	page, err := s.Events(context.Background(), 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	return page.Events
}

func TestFailureThresholdRecoveryDeduplicationAndStale(t *testing.T) {
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.RequestURI() != "/api/v1/status" || r.Header.Get("Authorization") != "Bearer machine-secret" {
			t.Errorf("not a fixed read-only request")
		}
		if fail.Load() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, validStatus)
	}))
	defer server.Close()
	p, s := testPoller(t, server.URL)
	now := time.Now().UTC()
	p.now = func() time.Time { return now }
	ctx := context.Background()
	initial := p.Snapshot()
	if initial.HeartbeatAt != nil || initial.Targets[0].State != "unknown" || !initial.Targets[0].Stale || initial.Targets[0].Status != nil {
		t.Fatal("bad initial observation")
	}
	p.cycle(ctx)
	o := p.Snapshot().Targets[0]
	if o.State != "online" || o.Stale || o.Status == nil || len(events(t, s)) != 0 {
		t.Fatalf("first success must not recover: %+v", o)
	}
	if p.Snapshot().HeartbeatAt == nil {
		t.Fatal("cycle did not heartbeat")
	}
	// A's old clock does not expire a freshly received observation.
	if o.SucceededAt == nil || !o.SucceededAt.Equal(now) {
		t.Fatal("success is not B reception time")
	}
	now = now.Add(90 * time.Second)
	if p.Snapshot().Targets[0].Stale {
		t.Fatal("stale must use strictly greater than threshold")
	}
	now = now.Add(time.Nanosecond)
	if !p.Snapshot().Targets[0].Stale {
		t.Fatal("cached observation not stale")
	}
	fail.Store(true)
	for i := 1; i <= 4; i++ {
		now = now.Add(time.Second)
		p.cycle(ctx)
		o = p.Snapshot().Targets[0]
		want := "online"
		if i >= 3 {
			want = "unreachable"
		}
		if o.State != want || o.Failures != i || !o.Stale || o.Status == nil || o.CheckedAt == nil {
			t.Fatalf("attempt %d: %+v", i, o)
		}
	}
	if es := events(t, s); len(es) != 1 || es[0].Kind != "unreachable" {
		t.Fatalf("outage event dedup: %+v", es)
	}
	fail.Store(false)
	p.cycle(ctx)
	p.cycle(ctx)
	if es := events(t, s); len(es) != 2 || es[0].Kind != "recovered" {
		t.Fatalf("recovery event dedup: %+v", es)
	}
	if o = p.Snapshot().Targets[0]; o.Failures != 0 || o.Stale || o.State != "online" {
		t.Fatalf("bad recovery: %+v", o)
	}
}

func TestImmediateErrorClassesRedirectAndActualBodyLimit(t *testing.T) {
	var redirected atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); io.WriteString(w, validStatus) }))
	defer sink.Close()
	cases := []struct {
		name, state string
		handler     http.HandlerFunc
		tls         bool
	}{
		{"unauthorized", "auth_error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }, false},
		{"forbidden", "auth_error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }, false},
		{"tls", "tls_error", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, validStatus) }, true},
		{"identity", "identity_mismatch", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, strings.Replace(validStatus, "node-a", "other-node", 1))
		}, false},
		{"redirect", "protocol_error", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, sink.URL, 302) }, false},
		{"unexpected status", "protocol_error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }, false},
		{"arbitrary JSON", "protocol_error", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"ok":true}`) }, false},
		{"wrong content type", "protocol_error", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, validStatus)
		}, false},
		{"chunked oversize", "protocol_error", func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			io.WriteString(w, strings.Repeat(" ", responseLimit+1))
		}, false},
		{"compressed oversize", "protocol_error", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			g := gzip.NewWriter(w)
			io.WriteString(g, strings.Repeat(" ", responseLimit+1))
			g.Close()
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				tc.handler(w, r)
			})
			var server *httptest.Server
			if tc.tls {
				server = httptest.NewTLSServer(h)
			} else {
				server = httptest.NewServer(h)
			}
			defer server.Close()
			p, s := testPoller(t, server.URL)
			p.cycle(context.Background())
			p.cycle(context.Background())
			o := p.Snapshot().Targets[0]
			if o.State != tc.state || !o.Stale || o.Failures != 2 || o.SucceededAt != nil {
				t.Fatalf("got %+v", o)
			}
			es := events(t, s)
			if len(es) != 1 || es[0].Kind != "error" || es[0].State != tc.state {
				t.Fatalf("events %+v", es)
			}
			body, _ := json.Marshal(p.Snapshot())
			if strings.Contains(string(body), "machine-secret") {
				t.Fatal("secret in API snapshot")
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect was followed (potential token disclosure)")
	}
}

func TestStatusSchema(t *testing.T) {
	if _, err := decodeStatus([]byte(validStatus)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{}`, `null`, validStatus + `{}`, strings.Replace(validStatus, `"apiVersion":"1"`, `"apiVersion":"2"`, 1),
		strings.Replace(validStatus, `"sampledAt":"2020-01-01T00:00:00Z"`, `"sampledAt":"not-a-date"`, 1),
		strings.Replace(validStatus, `"usagePercent":null`, `"usagePercent":101`, 1),
		strings.Replace(validStatus, `"logicalCount":2`, `"logicalCount":0`, 1),
		strings.Replace(validStatus, `"logicalCount":2`, `"logicalCount":null`, 1),
		strings.Replace(validStatus, `"uptimeSeconds":10`, `"uptimeSeconds":-1`, 1),
		strings.Replace(validStatus, `"totalBytes":100`, `"totalBytes":-1`, 1),
		strings.Replace(validStatus, `"totalBytes":100`, `"totalBytes":1.5`, 1),
		strings.Replace(validStatus, `"usedPercent":20`, `"usedPercent":101`, 1),
		strings.Replace(validStatus, `"platform":"test",`, "", 1),
		strings.Replace(validStatus, `"memory":null,`, "", 1),
		strings.Replace(validStatus, `"metricsScope":"host"`, `"metricsScope":"bogus"`, 1),
	} {
		if _, err := decodeStatus([]byte(body)); err == nil {
			t.Errorf("invalid schema accepted: %s", body)
		}
	}
	var fields map[string]json.RawMessage
	json.Unmarshal([]byte(validStatus), &fields)
	for key := range fields {
		var copy map[string]json.RawMessage
		json.Unmarshal([]byte(validStatus), &copy)
		delete(copy, key)
		b, _ := json.Marshal(copy)
		if _, err := decodeStatus(b); err == nil {
			t.Errorf("missing %s accepted", key)
		}
	}
}

func TestStatusRejectsCaseAliases(t *testing.T) {
	body := strings.Replace(validStatus, `"memory":null`, `"memory":{"totalBytes":200,"usedBytes":40,"usedPercent":20}`, 1)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &fields); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"root", "system", "cpu", "memory", "disk"} {
		raw := body
		if group != "root" {
			raw = string(fields[group])
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &nested); err != nil {
			t.Fatal(err)
		}
		for key, value := range nested {
			alias := fmt.Sprintf("%q:%s", strings.ToUpper(key), value)
			for _, order := range []string{"before", "after"} {
				t.Run(group+"/"+key+"/"+order, func(t *testing.T) {
					modified := strings.TrimSuffix(raw, "}") + "," + alias + "}"
					if order == "before" {
						modified = "{" + alias + "," + strings.TrimPrefix(raw, "{")
					}
					candidate := modified
					if group != "root" {
						candidate = strings.Replace(body, fmt.Sprintf("%q:%s", group, raw), fmt.Sprintf("%q:%s", group, modified), 1)
					}
					if _, err := decodeStatus([]byte(candidate)); err == nil {
						t.Fatal("accepted a non-canonical required field alias")
					}
				})
			}
		}
	}
	// These later aliases previously overwrote the canonical version/identity.
	for _, replacement := range []struct{ old, new string }{
		{`"apiVersion":"1"`, `"apiVersion":"wrong","APIVERSION":"1"`},
		{`"nodeId":"node-a"`, `"nodeId":"wrong","NODEID":"node-a"`},
		{`"usagePercent":null`, `"usagePercent":null,"uſagePercent":20`},
	} {
		if _, err := decodeStatus([]byte(strings.Replace(body, replacement.old, replacement.new, 1))); err == nil {
			t.Errorf("accepted override: %s", replacement.new)
		}
	}
}

func TestStatusAllowsNonConflictingExtensions(t *testing.T) {
	body := strings.Replace(validStatus, `"memory":null`, `"memory":{"totalBytes":200,"usedBytes":40,"usedPercent":20}`, 1)
	// Unknown fields may differ in case and contain keys reserved at other depths.
	body = strings.ReplaceAll(body, "{", `{"futureField":{"NODEID":"extension"},"FUTUREFIELD":true,`)
	s, err := decodeStatus([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if s.NodeID != "node-a" || s.APIVersion != "1" || s.CPU.LogicalCount != 2 || s.Memory == nil || s.Memory.TotalBytes != 200 || s.Disk == nil || s.Disk.TotalBytes != 100 {
		t.Fatal("extensions changed the canonical status")
	}
}

func TestRestartLoadsCacheWithoutFabricatingRecovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, validStatus)
	}))
	defer server.Close()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Defaults()
	targets := []config.Target{{ID: "a", Name: "A", URL: server.URL, ExpectedNodeID: "node-a", Token: "secret"}}
	p, err := New(c, targets, s, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	p.cycle(context.Background())
	original := p.Snapshot()
	o := original.Targets[0]
	o.State = "unreachable"
	o.Stale = true
	o.Failures = 3
	if err := s.Save(context.Background(), o, nil); err != nil {
		t.Fatal(err)
	}
	p.client.CloseIdleConnections()
	s.Close()
	s, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p, err = New(c, targets, s, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	m := p.Snapshot()
	o = m.Targets[0]
	if m.InstanceID == original.InstanceID || m.HeartbeatAt != nil || o.State != "unknown" || !o.Stale || o.Status == nil || o.SucceededAt == nil {
		t.Fatalf("bad restart %+v", m)
	}
	p.cycle(context.Background())
	if len(events(t, s)) != 0 {
		t.Fatal("restart fabricated a recovery from persisted outage")
	}
	targets[0].ExpectedNodeID = "replacement"
	replacement, err := New(c, targets, s, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.client.CloseIdleConnections()
	if replacement.Snapshot().Targets[0].Status != nil {
		t.Fatal("reused id exposed old target status")
	}
}

func TestBoundedConcurrencyHeartbeatAndCancellation(t *testing.T) {
	var active, maxActive atomic.Int32
	var mu sync.Mutex
	byTarget := map[string]bool{}
	started := make(chan struct{}, 32)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		mu.Lock()
		if byTarget[key] {
			t.Error("same target overlapped")
		}
		byTarget[key] = true
		mu.Unlock()
		defer func() { mu.Lock(); delete(byTarget, key); mu.Unlock() }()
		n := active.Add(1)
		defer active.Add(-1)
		for old := maxActive.Load(); n > old && !maxActive.CompareAndSwap(old, n); old = maxActive.Load() {
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, validStatus)
	}))
	defer server.Close()
	p, s := testPoller(t, server.URL)
	targets := make([]config.Target, 24)
	for i := range targets {
		targets[i] = config.Target{ID: fmt.Sprint(i), Name: "A", URL: server.URL, ExpectedNodeID: "node-a", Token: fmt.Sprint(i)}
	}
	var err error
	p, err = New(p.config, targets, s, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	defer p.client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	for i := 0; i < concurrency; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	if p.Snapshot().HeartbeatAt != nil {
		t.Fatal("HTTP snapshot fabricated heartbeat before polling completed")
	}
	cancel()
	unblock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not stop poller")
	}
	if maxActive.Load() > concurrency {
		t.Fatalf("concurrency %d", maxActive.Load())
	}
	if len(events(t, s)) != 0 {
		t.Fatal("shutdown fabricated events")
	}
}

func TestTimeoutMalformedHTTPAndErrorRecovery(t *testing.T) {
	t.Run("total timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		p, _ := testPoller(t, server.URL)
		started := time.Now()
		p.cycle(context.Background())
		if elapsed := time.Since(started); elapsed > 3*time.Second {
			t.Fatalf("client total timeout was not enforced: %v", elapsed)
		}
		o := p.Snapshot().Targets[0]
		if o.State != "unknown" || o.Failures != 1 || !o.Stale {
			t.Fatalf("timeout classification: %+v", o)
		}
	})
	t.Run("malformed HTTP is immediate protocol error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			io.WriteString(conn, "INVALID HTTP RESPONSE\r\n\r\n")
		}))
		defer server.Close()
		p, _ := testPoller(t, server.URL)
		p.cycle(context.Background())
		if state := p.Snapshot().Targets[0].State; state != "protocol_error" {
			t.Fatalf("malformed response: %s", state)
		}
	})
	t.Run("error to online and consecutive network failures", func(t *testing.T) {
		var mode atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch mode.Load() {
			case 0:
				w.WriteHeader(401)
			case 1:
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				conn.Close()
			default:
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, validStatus)
			}
		}))
		defer server.Close()
		p, s := testPoller(t, server.URL)
		ctx := context.Background()
		p.cycle(ctx)
		mode.Store(1)
		p.cycle(ctx)
		p.cycle(ctx)
		if p.Snapshot().Targets[0].State != "auth_error" {
			t.Fatal("non-network error accelerated network threshold")
		}
		mode.Store(0)
		p.cycle(ctx) // Reset consecutive network-failure count.
		mode.Store(1)
		p.cycle(ctx)
		p.cycle(ctx)
		if p.Snapshot().Targets[0].State != "auth_error" {
			t.Fatal("network failures were not consecutive")
		}
		mode.Store(2)
		p.cycle(ctx)
		p.cycle(ctx)
		es := events(t, s)
		if len(es) != 2 || es[0].Kind != "recovered" || es[1].Kind != "error" {
			t.Fatalf("error recovery dedup: %+v", es)
		}
	})
}

func TestEmptyTargetsLoopHeartbeat(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := config.Defaults()
	c.PollIntervalSeconds = 1
	p, err := New(c, nil, s, "monitor")
	if err != nil {
		t.Fatal(err)
	}
	p.cycle(context.Background())
	m := p.Snapshot()
	if m.Targets == nil || len(m.Targets) != 0 || m.HeartbeatAt == nil {
		t.Fatalf("empty loop %+v", m)
	}
}
