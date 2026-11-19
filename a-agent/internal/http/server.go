package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"fleetops/a-agent/internal/auth"
	"fleetops/a-agent/internal/collector"
	"fleetops/a-agent/internal/config"
)

const (
	SessionPath  = "/api/v1/session"
	StatusPath   = "/api/v1/status"
	MaxBodyBytes = 32 * 1024
)

type StatusSource interface {
	Status() (collector.Status, bool)
}

type Handler struct {
	auth    *auth.Manager
	status  StatusSource
	origins map[string]bool
	limiter *loginLimiter
}

func NewHandler(c config.Config, manager *auth.Manager, source StatusSource) *Handler {
	origins := make(map[string]bool, len(c.AllowedOrigins))
	for _, origin := range c.AllowedOrigins {
		origins[origin] = true
	}
	return &Handler{auth: manager, status: source, origins: origins, limiter: newLimiter()}
}

func NewServer(c config.Config, manager *auth.Manager, source StatusSource) *http.Server {
	return &http.Server{
		Addr: c.Listen, Handler: NewHandler(c, manager, source),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 * 1024,
		// No request headers, payloads, credentials or panic values enter logs.
		ErrorLog: log.New(io.Discard, "", 0),
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	b, err := json.Marshal(value)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":{"code":"internal_error","message":"response unavailable"}}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
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

func authError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUnauthorized):
		writeError(w, 401, "unauthorized", "invalid or expired authentication")
	case errors.Is(err, auth.ErrForbidden):
		writeError(w, 403, "forbidden", "machine token cannot operate on sessions")
	case errors.Is(err, auth.ErrSessionLimit):
		writeError(w, 429, "session_limit", "session capacity reached")
	default:
		writeError(w, 503, "authorization_unavailable", "authorization state unavailable")
	}
}

func methods(path string) string {
	switch path {
	case SessionPath:
		return "GET, POST, DELETE"
	case StatusPath:
		return "GET"
	default:
		return ""
	}
}

func methodAllowed(method, allowed string) bool {
	for _, candidate := range strings.Split(allowed, ", ") {
		if method == candidate {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Add("Vary", "Origin")
	defer func() {
		if recover() != nil {
			writeError(w, 500, "internal_error", "request could not be completed")
		}
	}()

	origins := r.Header.Values("Origin")
	if len(origins) > 0 {
		if len(origins) != 1 || origins[0] == "" || !h.origins[origins[0]] {
			writeError(w, 403, "origin_forbidden", "origin not allowed")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origins[0])
	}
	allowed := methods(r.URL.Path)
	if allowed == "" {
		writeError(w, 404, "not_found", "endpoint not found")
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")
		requested := r.Header.Values("Access-Control-Request-Method")
		if len(origins) != 1 || len(requested) != 1 || !methodAllowed(requested[0], allowed) {
			writeError(w, 403, "preflight_forbidden", "preflight method or origin not allowed")
			return
		}
		for _, line := range r.Header.Values("Access-Control-Request-Headers") {
			for _, header := range strings.Split(line, ",") {
				name := strings.ToLower(strings.TrimSpace(header))
				if name != "authorization" && name != "content-type" {
					writeError(w, 403, "preflight_forbidden", "preflight header not allowed")
					return
				}
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", allowed)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !methodAllowed(r.Method, allowed) {
		w.Header().Set("Allow", allowed+", OPTIONS")
		writeError(w, 405, "method_not_allowed", "method not allowed")
		return
	}
	// Check the actual body size before side effects; ContentLength is not trusted.
	body := http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, 413, "body_too_large", "request body exceeds 32 KiB")
		} else {
			writeError(w, 400, "invalid_json", "invalid request body")
		}
		return
	}
	if r.URL.Path == SessionPath && r.Method == http.MethodPost {
		h.login(w, r, data)
		return
	}
	token := bearer(r)
	if r.Method == http.MethodDelete {
		if err := h.auth.Logout(token); err != nil {
			authError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	principal, err := h.auth.Authenticate(token, r.URL.Path == StatusPath)
	if err != nil {
		authError(w, err)
		return
	}
	if r.URL.Path == SessionPath {
		writeJSON(w, 200, principal)
		return
	}
	sample, ready := h.status.Status()
	if !ready || sample.NodeID != principal.NodeID {
		writeError(w, 503, "sample_unavailable", "initial sample not available")
		return
	}
	writeJSON(w, 200, sample)
}

func bearer(r *http.Request) string {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return ""
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 512 {
		return ""
	}
	return parts[1]
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request, data []byte) {
	if !h.limiter.allow(r.RemoteAddr) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "rate_limited", "too many login attempts")
		return
	}
	if len(r.Header.Values("Authorization")) > 0 {
		if _, err := h.auth.Authenticate(bearer(r), false); err != nil {
			authError(w, err)
			return
		}
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, 415, "unsupported_media_type", "application/json is required")
		return
	}
	credential, ok := decodeCredential(data)
	if !ok {
		writeError(w, 400, "invalid_json", "expected a JSON object containing only credential")
		return
	}
	session, err := h.auth.Login(credential)
	if err != nil {
		authError(w, err)
		return
	}
	writeJSON(w, 200, session)
}

// Token-level decoding rejects duplicate keys, null, extra fields and trailing JSON.
func decodeCredential(data []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') || !dec.More() {
		return "", false
	}
	key, err := dec.Token()
	if err != nil || key != "credential" {
		return "", false
	}
	var credential string
	value, err := dec.Token()
	if err != nil {
		return "", false
	}
	credential, ok := value.(string)
	if !ok || len(credential) < 1 || len(credential) > 512 || dec.More() {
		return "", false
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return "", false
	}
	_, err = dec.Token()
	return credential, err == io.EOF
}
