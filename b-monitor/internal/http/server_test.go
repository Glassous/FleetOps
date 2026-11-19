package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fleetops/b-monitor/internal/auth"
	"fleetops/b-monitor/internal/config"
	"fleetops/b-monitor/internal/store"
)

type source struct {
	db   *store.Store
	node string
}

func (s source) Snapshot() store.Monitor {
	return store.Monitor{APIVersion: "1", MonitorID: s.node, InstanceID: "instance", StartedAt: time.Now().UTC(), GeneratedAt: time.Now().UTC(), StaleAfterSeconds: 90, StorageHealthy: s.db.Healthy(), Targets: []store.Observation{}}
}

type fixture struct {
	handler    http.Handler
	credential auth.Credential
	dir        string
	db         *store.Store
}

func setup(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	credential, err := auth.ChangeCredential(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	c := config.Defaults()
	c.AllowedOrigins = []string{"https://console.example"}
	server := New(c, a, source{s, credential.NodeID}, s)
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes > 32<<10 {
		t.Fatal("unsafe server limits")
	}
	return fixture{handler: server.Handler, credential: credential, dir: dir, db: s}
}

func request(f fixture, method, path, token, origin, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func login(t *testing.T, f fixture) auth.Session {
	t.Helper()
	w := request(f, "POST", "/api/v1/session", "", "", fmt.Sprintf(`{"credential":%q}`, f.credential.Credential))
	if w.Code != 200 {
		t.Fatalf("login %d: %s", w.Code, w.Body.String())
	}
	var session auth.Session
	if err := json.Unmarshal(w.Body.Bytes(), &session); err != nil || session.Token == "" || session.NodeID != f.credential.NodeID {
		t.Fatal("invalid session")
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatal("cookie emitted")
	}
	return session
}

func TestSessionAuthReadOnlyAndRotation(t *testing.T) {
	f := setup(t)
	for _, path := range []string{"/api/v1/monitor", "/api/v1/events", "/api/v1/session"} {
		if w := request(f, "GET", path, "", "", ""); w.Code != 401 {
			t.Fatalf("unauthenticated desktop request %s: %d", path, w.Code)
		}
	}
	if w := request(f, "GET", "/api/v1/monitor", f.credential.Credential, "", ""); w.Code != 401 {
		t.Fatal("bootstrap credential treated as bearer")
	}
	session := login(t, f)
	w := request(f, "GET", "/api/v1/session", session.Token, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), session.Token) || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatal("session identity leaks token")
	}
	for _, path := range []string{"/api/v1/monitor", "/api/v1/events"} {
		w = request(f, "GET", path, session.Token, "", "")
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("read %s: %d", path, w.Code)
		}
		if strings.Contains(w.Body.String(), f.credential.Credential) {
			t.Fatal("credential in response")
		}
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/reboot", "/api/v1/targets", "/api/v1/proxy?url=http://localhost"} {
		if w := request(f, "GET", path, session.Token, "", ""); w.Code != 404 {
			t.Fatalf("unexpected endpoint %s: %d", path, w.Code)
		}
	}
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "HEAD"} {
		if w := request(f, method, "/api/v1/monitor", session.Token, "", ""); w.Code != 405 {
			t.Fatalf("write allowed: %s", method)
		}
	}
	if w := request(f, "DELETE", "/api/v1/session", session.Token, "", ""); w.Code != 204 || w.Body.Len() != 0 {
		t.Fatal("logout failed")
	}
	if w := request(f, "GET", "/api/v1/monitor", session.Token, "", ""); w.Code != 401 {
		t.Fatal("revoked session still works")
	}
	session = login(t, f)
	if _, err := auth.ChangeCredential(f.dir, true); err != nil {
		t.Fatal(err)
	}
	if w := request(f, "GET", "/api/v1/monitor", session.Token, "", ""); w.Code != 401 {
		t.Fatal("rotation not observed by service")
	}
}

func TestExactCORSAndTokenlessPreflight(t *testing.T) {
	f := setup(t)
	origin := "https://console.example"
	w := request(f, "GET", "/api/v1/monitor", "", origin, "")
	if w.Code != 401 || w.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Fatal("legal origin 401 lacks CORS")
	}
	for _, bad := range []string{"https://console.example.evil", "http://console.example", "null", "https://console.example/"} {
		w = request(f, "GET", "/api/v1/monitor", "", bad, "")
		if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("non-exact origin accepted: %s", bad)
		}
	}
	r := httptest.NewRequest("OPTIONS", "/api/v1/session", nil)
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "authorization, CONTENT-TYPE")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("preflight rejected or allows cookies")
	}
	r.Header.Set("Access-Control-Request-Headers", "X-Secret")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("arbitrary preflight header allowed")
	}
	r.Header.Set("Access-Control-Request-Headers", "Authorization")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("arbitrary preflight method allowed")
	}
	session := login(t, f)
	w = request(f, "GET", "/api/v1/monitor", session.Token, origin, "")
	if w.Code != 200 || w.Header().Get("Access-Control-Allow-Origin") != origin {
		t.Fatal("CORS authenticated request failed")
	}
	r = httptest.NewRequest("GET", "/api/v1/monitor", nil)
	r.Header.Add("Origin", origin)
	r.Header.Add("Origin", origin)
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("multiple origins accepted")
	}
}

func TestBodyLimitsErrorsAndLoginRateLimit(t *testing.T) {
	f := setup(t)
	for _, body := range []string{`{}`, `null`, `{"credential":""}`, `{"credential":"x","extra":true}`, `{"credential":"x"}{}`, `{"credential":5}`} {
		w := request(f, "POST", "/api/v1/session", "", "", body)
		if w.Code != 400 {
			t.Errorf("invalid JSON %s: %d", body, w.Code)
		}
		var envelope map[string]map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil || envelope["error"]["code"] == "" || envelope["error"]["message"] == "" {
			t.Fatal("missing error envelope")
		}
	}
	w := request(f, "POST", "/api/v1/session", "", "", `{"credential":"`+strings.Repeat("x", 33000)+`"}`)
	if w.Code != 413 {
		t.Fatalf("oversize content-length accepted: %d", w.Code)
	}
	r := httptest.NewRequest("POST", "/api/v1/session", strings.NewReader(`{"credential":"x"}`+strings.Repeat(" ", 33000)))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("streaming body oversize accepted: %d", w.Code)
	}
	for i := 0; i < 5; i++ {
		if w = request(f, "POST", "/api/v1/session", "", "", `{"credential":"wrong"}`); w.Code != 401 {
			t.Fatalf("wrong credential %d", w.Code)
		}
	}
	w = request(f, "POST", "/api/v1/session", "", "", `{"credential":"wrong"}`)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("login not rate limited")
	}
}

func TestOversizedDeleteDoesNotRevokeSession(t *testing.T) {
	for _, length := range []int64{-1, 1, 32769} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			f := setup(t)
			session := login(t, f)
			r := httptest.NewRequest("DELETE", "/api/v1/session", strings.NewReader(strings.Repeat("x", 32769)))
			r.ContentLength = length
			r.Header.Set("Authorization", "Bearer "+session.Token)
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, r)
			if w.Code != 413 {
				t.Fatalf("oversized DELETE returned %d", w.Code)
			}
			if request(f, "GET", "/api/v1/session", session.Token, "", "").Code != 200 {
				t.Fatal("oversized DELETE revoked session")
			}
		})
	}
}

func TestPaginationValidationAndStorageFailure(t *testing.T) {
	f := setup(t)
	session := login(t, f)
	for _, query := range []string{"limit=0", "limit=101", "limit=-1", "limit=1&limit=2", "before=0", "before=-1", "before=9223372036854775808", "before=1%20OR%201=1", "before=1;DROP", "before=", "limit=1.5", "before=%2B1", "url=http://localhost"} {
		if w := request(f, "GET", "/api/v1/events?"+query, session.Token, "", ""); w.Code != 400 {
			t.Errorf("invalid pagination %q: %d", query, w.Code)
		}
	}
	w := request(f, "GET", "/api/v1/events?limit=1&before=9223372036854775807", session.Token, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"events":[]`) || !strings.Contains(w.Body.String(), `"nextBefore":null`) {
		t.Fatalf("empty page %s", w.Body.String())
	}
	f.db.Close()
	if w := request(f, "GET", "/api/v1/events", session.Token, "", ""); w.Code != 503 {
		t.Fatal("closed storage reported success")
	}
	w = request(f, "GET", "/api/v1/monitor", session.Token, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"storageHealthy":false`) {
		t.Fatal("storage read failure not exposed")
	}
}
