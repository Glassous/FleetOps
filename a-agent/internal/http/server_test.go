package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fleetops/a-agent/internal/auth"
	"fleetops/a-agent/internal/collector"
	"fleetops/a-agent/internal/config"
)

const allowedOrigin = "https://web.example"

type fixedSource struct {
	sample collector.Status
	ready  bool
	calls  int
}

func (s *fixedSource) Status() (collector.Status, bool) { s.calls++; return s.sample, s.ready }

type fixture struct {
	h        *Handler
	store    auth.Store
	identity auth.Identity
	source   *fixedSource
}

func setup(t *testing.T) fixture {
	t.Helper()
	store := auth.Store{Dir: filepath.Join(t.TempDir(), "data")}
	identity, err := store.Init()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	source := &fixedSource{ready: true, sample: collector.Status{
		APIVersion: "1", NodeID: identity.NodeID, Hostname: "test-host", AgentVersion: "0.1.0", MetricsScope: "host",
		System:    collector.System{OS: "linux", Platform: "debian", Kernel: "6.1", Arch: "amd64"},
		SampledAt: now, AgentStartedAt: now, UptimeSeconds: 10000, CPU: collector.CPU{LogicalCount: 4},
	}}
	h := NewHandler(config.Config{AllowedOrigins: []string{allowedOrigin}}, auth.NewManager(store), source)
	return fixture{h: h, store: store, identity: identity, source: source}
}

func request(h http.Handler, method, path, body, token string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:4321"
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func checkCode(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d; body: %s", w.Code, want, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("cache or cookie policy")
	}
	if want >= 400 {
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Error.Code == "" || body.Error.Message == "" {
			t.Fatal("incorrect error envelope")
		}
	}
}

func login(t *testing.T, f fixture) auth.Session {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"credential": f.identity.Credential})
	w := request(f.h, "POST", SessionPath, string(body), "", nil)
	checkCode(t, w, 200)
	var result auth.Session
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.NodeID != f.identity.NodeID || result.Token == "" || result.ExpiresAt.Before(time.Now().Add(7*time.Hour)) {
		t.Fatal("bad login response")
	}
	return result
}

func TestSessionLifecycleStatusAndLiveRotation(t *testing.T) {
	f := setup(t)
	checkCode(t, request(f.h, "POST", SessionPath, `{"credential":"wrong-secret"}`, "", nil), 401)
	session := login(t, f)
	w := request(f.h, "GET", SessionPath, "", session.Token, nil)
	checkCode(t, w, 200)
	var identity map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &identity)
	if len(identity) != 2 || identity["nodeId"] != f.identity.NodeID || identity["expiresAt"] == nil || strings.Contains(w.Body.String(), session.Token) {
		t.Fatal("GET session exposed token or wrong fields")
	}
	w = request(f.h, "GET", StatusPath, "", session.Token, nil)
	checkCode(t, w, 200)
	var status collector.Status
	if json.Unmarshal(w.Body.Bytes(), &status) != nil || status.NodeID != f.identity.NodeID || status.CPU.UsagePercent != nil || status.Memory != nil || status.Disk != nil {
		t.Fatal("incorrect status shape")
	}
	if f.source.calls != 1 {
		t.Fatal("status cache not used")
	}
	f.source.ready = false
	checkCode(t, request(f.h, "GET", StatusPath, "", session.Token, nil), 503)
	f.source.ready = true
	w = request(f.h, "DELETE", SessionPath, "", session.Token, nil)
	checkCode(t, w, 204)
	if w.Body.Len() != 0 {
		t.Fatal("204 has body")
	}
	checkCode(t, request(f.h, "GET", SessionPath, "", session.Token, nil), 401)
	session = login(t, f)
	rotated, err := f.store.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	checkCode(t, request(f.h, "GET", StatusPath, "", session.Token, nil), 401)
	checkCode(t, request(f.h, "POST", SessionPath, fmt.Sprintf(`{"credential":%q}`, f.identity.Credential), "", nil), 401)
	f.identity = rotated
	_ = login(t, f)
}

func TestMachineTokenCannotOperateSessionsAndRevokesLive(t *testing.T) {
	f := setup(t)
	token, err := f.store.Issue("monitor")
	if err != nil {
		t.Fatal(err)
	}
	checkCode(t, request(f.h, "GET", StatusPath, "", token.Token, nil), 200)
	for _, method := range []string{"GET", "DELETE", "POST"} {
		checkCode(t, request(f.h, method, SessionPath, fmt.Sprintf(`{"credential":%q}`, f.identity.Credential), token.Token, nil), 403)
	}
	if err := f.store.Revoke(token.ID); err != nil {
		t.Fatal(err)
	}
	checkCode(t, request(f.h, "GET", StatusPath, "", token.Token, nil), 401)
	checkCode(t, request(f.h, "GET", StatusPath, "", "", nil), 401)
	if f.source.calls != 1 {
		t.Fatal("unauthorized request reached status")
	}
}

func TestCORSOriginAnd401(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct {
		origin string
		want   int
		cors   bool
	}{
		{allowedOrigin, 401, true}, {"https://evil.example", 403, false}, {allowedOrigin + ".evil", 403, false},
		{"null", 403, false}, {"", 403, false}, {allowedOrigin + "/", 403, false},
	} {
		w := request(f.h, "GET", StatusPath, "", "", map[string]string{"Origin": tc.origin})
		checkCode(t, w, tc.want)
		if (w.Header().Get("Access-Control-Allow-Origin") == allowedOrigin) != tc.cors {
			t.Fatal("incorrect CORS origin")
		}
		if !strings.Contains(strings.Join(w.Header().Values("Vary"), ","), "Origin") {
			t.Fatal("Vary Origin missing")
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("cookie credentials enabled")
		}
	}
	checkCode(t, request(f.h, "GET", StatusPath, "", "", nil), 401)
	session := login(t, f)
	checkCode(t, request(f.h, "GET", StatusPath, "", session.Token, map[string]string{"Origin": "https://evil.example"}), 403)
	checkCode(t, request(f.h, "GET", StatusPath, "", session.Token, nil), 200)
	r := httptest.NewRequest("GET", StatusPath, nil)
	r.Header.Add("Origin", allowedOrigin)
	r.Header.Add("Origin", allowedOrigin)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	checkCode(t, w, 403)
}

func TestCORSPreflight(t *testing.T) {
	f := setup(t)
	for _, tc := range []struct {
		path, method, headers string
		want                  int
	}{
		{SessionPath, "POST", "Authorization, Content-Type", 204},
		{SessionPath, "DELETE", "authorization", 204},
		{StatusPath, "GET", "content-type", 204},
		{StatusPath, "GET", "", 204},
		{StatusPath, "POST", "Authorization", 403},
		{StatusPath, "GET", "X-Admin", 403},
		{StatusPath, "GET", "Authorization,", 403},
		{SessionPath, "PATCH", "Content-Type", 403},
		{SessionPath, "", "Content-Type", 403},
	} {
		headers := map[string]string{"Origin": allowedOrigin, "Access-Control-Request-Method": tc.method}
		if tc.headers != "" {
			headers["Access-Control-Request-Headers"] = tc.headers
		}
		w := request(f.h, "OPTIONS", tc.path, "", "", headers)
		checkCode(t, w, tc.want)
		if tc.want == 204 && (w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type") {
			t.Fatal("invalid successful preflight")
		}
	}
	checkCode(t, request(f.h, "OPTIONS", StatusPath, "", "", nil), 403)
	checkCode(t, request(f.h, "OPTIONS", StatusPath, "", "", map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"}), 403)
}

func TestJSONBodyLimitAndSanitizedErrors(t *testing.T) {
	for _, body := range []string{"", "null", "[]", `{}`, `{"credential":null}`, `{"credential":42}`, `{"credential":""}`, `{"credential":"x","extra":"SECRET_VALUE"}`, `{"credential":"x","credential":"y"}`, `{"credential":"x"} {}`, `{"credential":"` + strings.Repeat("x", 513) + `"}`} {
		f := setup(t)
		w := request(f.h, "POST", SessionPath, body, "", nil)
		checkCode(t, w, 400)
		if strings.Contains(w.Body.String(), "SECRET_VALUE") {
			t.Fatal("request secret leaked")
		}
	}
	f := setup(t)
	body := `{"credential":"wrong"}`
	body += strings.Repeat(" ", MaxBodyBytes-len(body))
	checkCode(t, request(f.h, "POST", SessionPath, body, "", nil), 401)
	checkCode(t, request(f.h, "POST", SessionPath, body+" ", "", nil), 413)
	checkCode(t, request(f.h, "POST", SessionPath, body, "", map[string]string{"Content-Type": "text/plain"}), 415)
}

func TestAPIBodyLimitBeforeSideEffects(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, SessionPath},
		{http.MethodGet, SessionPath},
		{http.MethodDelete, SessionPath},
		{http.MethodGet, StatusPath},
	} {
		for _, size := range []int{MaxBodyBytes, MaxBodyBytes + 1} {
			for _, length := range []struct {
				name  string
				value int64
			}{
				{"known", int64(size)}, {"unknown", -1}, {"underreported", 1}, {"zero", 0},
			} {
				t.Run(fmt.Sprintf("%s%s/%d/%s", route.method, route.path, size, length.name), func(t *testing.T) {
					f := setup(t)
					session := login(t, f)
					body := fmt.Sprintf(`{"credential":%q}`, f.identity.Credential)
					body += strings.Repeat(" ", size-len(body))
					r := httptest.NewRequest(route.method, route.path, io.NopCloser(strings.NewReader(body)))
					r.ContentLength = length.value
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("Authorization", "Bearer "+session.Token)
					w := httptest.NewRecorder()
					f.h.ServeHTTP(w, r)
					if size > MaxBodyBytes {
						checkCode(t, w, http.StatusRequestEntityTooLarge)
						if w.Header().Get("Content-Type") != "application/json" || !strings.Contains(w.Body.String(), `"code":"body_too_large"`) {
							t.Fatal("incorrect body limit error protocol")
						}
						if f.source.calls != 0 {
							t.Fatal("oversized request reached status source")
						}
						checkCode(t, request(f.h, "GET", SessionPath, "", session.Token, nil), 200)
					} else if route.method == http.MethodDelete {
						checkCode(t, w, 204)
						checkCode(t, request(f.h, "GET", SessionPath, "", session.Token, nil), 401)
					} else {
						checkCode(t, w, 200)
					}
				})
			}
		}
	}
}

type failedBodyReader struct{}

func (failedBodyReader) Read([]byte) (int, error) {
	return 0, errors.New("SECRET_READ_ERROR")
}

func TestBodyReadFailureDoesNotLogout(t *testing.T) {
	f := setup(t)
	session := login(t, f)
	r := httptest.NewRequest(http.MethodDelete, SessionPath, io.MultiReader(strings.NewReader("partial body"), failedBodyReader{}))
	r.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	checkCode(t, w, 400)
	if strings.Contains(w.Body.String(), "SECRET_READ_ERROR") {
		t.Fatal("body read error leaked")
	}
	checkCode(t, request(f.h, "GET", SessionPath, "", session.Token, nil), 200)
}

func TestLimiterBoundedExpiresAndIgnoresForwardedFor(t *testing.T) {
	f := setup(t)
	now := time.Now()
	f.h.limiter.now = func() time.Time { return now }
	for i := 0; i < loginAttempts; i++ {
		checkCode(t, request(f.h, "POST", SessionPath, `{"credential":"bad"}`, "", map[string]string{"X-Forwarded-For": fmt.Sprintf("10.0.0.%d", i)}), 401)
	}
	w := request(f.h, "POST", SessionPath, `{"credential":"bad"}`, "", nil)
	checkCode(t, w, 429)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing retry guidance")
	}
	now = now.Add(loginWindow)
	checkCode(t, request(f.h, "POST", SessionPath, `{"credential":"bad"}`, "", nil), 401)
	l := newLimiter()
	l.now = func() time.Time { return now }
	for i := 0; i < limiterCapacity; i++ {
		l.entries[fmt.Sprint(i)] = bucket{expires: now.Add(loginWindow)}
	}
	if l.allow("10.0.0.1:99") || len(l.entries) != limiterCapacity {
		t.Fatal("limiter exceeded capacity")
	}
	now = now.Add(loginWindow)
	if !l.allow("10.0.0.1:99") || len(l.entries) != 1 {
		t.Fatal("limiter expired entries not cleaned")
	}
}

func TestRoutingAndServerLimits(t *testing.T) {
	f := setup(t)
	checkCode(t, request(f.h, "GET", "/status", "", "", nil), 404)
	checkCode(t, request(f.h, "POST", StatusPath, "", "", nil), 405)
	checkCode(t, request(f.h, "HEAD", StatusPath, "", "", nil), 405)
	s := NewServer(config.Config{Listen: "127.0.0.1:18080"}, auth.NewManager(f.store), f.source)
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second || s.WriteTimeout != 10*time.Second || s.IdleTimeout != 60*time.Second || s.MaxHeaderBytes != 16*1024 {
		t.Fatal("incorrect HTTP limits")
	}
}
