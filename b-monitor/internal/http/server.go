package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fleetops/b-monitor/internal/auth"
	"fleetops/b-monitor/internal/config"
	"fleetops/b-monitor/internal/store"
)

type MonitorSource interface{ Snapshot() store.Monitor }

type API struct {
	auth    *auth.Manager
	monitor MonitorSource
	store   *store.Store
	origins map[string]bool
}

func New(c config.Config, a *auth.Manager, m MonitorSource, s *store.Store) *http.Server {
	api := &API{auth: a, monitor: m, store: s, origins: make(map[string]bool)}
	for _, origin := range c.AllowedOrigins {
		api.origins[origin] = true
	}
	return &http.Server{Addr: c.Listen, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{Error: struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}})
}

func methods(path string) string {
	switch path {
	case "/api/v1/session":
		return "GET, POST, DELETE"
	case "/api/v1/monitor", "/api/v1/events":
		return "GET"
	default:
		return ""
	}
}

func supports(list, method string) bool {
	for _, m := range strings.Split(list, ", ") {
		if method == m {
			return true
		}
	}
	return false
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Add("Vary", "Origin")
	origins := r.Header.Values("Origin")
	origin := r.Header.Get("Origin")
	if len(origins) > 0 {
		if len(origins) != 1 || origin == "" || !a.origins[origin] {
			failure(w, 403, "origin_denied", "Origin is not allowed")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	if r.Method == http.MethodOptions {
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")
		allowed := methods(r.URL.Path)
		if origin == "" || !supports(allowed, r.Header.Get("Access-Control-Request-Method")) || allowed == "" {
			failure(w, 403, "preflight_denied", "Preflight is not allowed")
			return
		}
		for _, h := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
			h = strings.ToLower(strings.TrimSpace(h))
			if h != "" && h != "authorization" && h != "content-type" {
				failure(w, 403, "preflight_denied", "Requested header is not allowed")
				return
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", allowed)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	body := http.MaxBytesReader(w, r.Body, 32<<10)
	data, readErr := io.ReadAll(body)
	body.Close()
	if readErr != nil {
		bodyError(w, readErr)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if r.URL.Path == "/api/v1/session" && r.Method == http.MethodPost {
		a.login(w, r)
		return
	}
	var session auth.Session
	headers := r.Header.Values("Authorization")
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(headers) != 1 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 512 {
		failure(w, 401, "unauthorized", "Authentication required")
		return
	}
	var err error
	session, err = a.auth.Authenticate(parts[1], r.URL.Path == "/api/v1/session" && r.Method == http.MethodDelete)
	if err != nil {
		authFailure(w, err)
		return
	}
	allowed := methods(r.URL.Path)
	if allowed == "" {
		failure(w, 404, "not_found", "Endpoint not found")
		return
	}
	if !supports(allowed, r.Method) {
		w.Header().Set("Allow", allowed)
		failure(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	switch r.URL.Path {
	case "/api/v1/session":
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, 200, session)
	case "/api/v1/monitor":
		writeJSON(w, 200, a.monitor.Snapshot())
	case "/api/v1/events":
		a.events(w, r)
	}
}

func authFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrLimited):
		w.Header().Set("Retry-After", "12")
		failure(w, 429, "rate_limited", "Login rate limited or session capacity reached")
	case errors.Is(err, auth.ErrUnavailable):
		failure(w, 503, "identity_unavailable", "Identity state unavailable")
	default:
		failure(w, 401, "unauthorized", "Invalid or expired credential or session")
	}
}

func bodyError(w http.ResponseWriter, err error) {
	var large *http.MaxBytesError
	if errors.As(err, &large) {
		failure(w, 413, "body_too_large", "Request body exceeds 32 KiB")
	} else {
		failure(w, 400, "invalid_request", "Expected one JSON object containing credential")
	}
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		failure(w, 415, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	var body struct {
		Credential string `json:"credential"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		bodyError(w, err)
		return
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		bodyError(w, err)
		return
	}
	if len(body.Credential) < 1 || len(body.Credential) > 512 {
		failure(w, 400, "invalid_request", "credential must be 1 to 512 bytes")
		return
	}
	// Do not trust X-Forwarded-For from direct clients; the global limiter also
	// bounds login attempts when deployments share a reverse-proxy address.
	client, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		client = r.RemoteAddr
	}
	session, err := a.auth.Login(body.Credential, client)
	if err != nil {
		authFailure(w, err)
		return
	}
	writeJSON(w, 200, session)
}

func positive(value string) (int64, error) {
	if value == "" {
		return 0, errors.New("empty integer")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("invalid integer")
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("invalid positive int64")
	}
	return n, nil
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		failure(w, 400, "invalid_pagination", "Invalid pagination")
		return
	}
	limit := int64(50)
	var before *int64
	for key, values := range query {
		if (key != "limit" && key != "before") || len(values) != 1 {
			failure(w, 400, "invalid_pagination", "Invalid pagination")
			return
		}
		n, err := positive(values[0])
		if err != nil || (key == "limit" && n > 100) {
			failure(w, 400, "invalid_pagination", "Invalid pagination")
			return
		}
		if key == "limit" {
			limit = n
		} else {
			before = &n
		}
	}
	page, err := a.store.Events(r.Context(), int(limit), before)
	if err != nil {
		failure(w, 503, "storage_unavailable", "Event storage unavailable")
		return
	}
	writeJSON(w, 200, page)
}
