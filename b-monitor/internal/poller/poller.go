package poller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"fleetops/b-monitor/internal/auth"
	"fleetops/b-monitor/internal/config"
	"fleetops/b-monitor/internal/store"
)

const responseLimit = 1 << 20
const concurrency = 8

type Poller struct {
	mu              sync.RWMutex
	cycleMu         sync.Mutex
	config          config.Config
	targets         []config.Target
	observations    map[string]store.Observation
	networkFailures map[string]int
	client          *http.Client
	store           *store.Store
	monitorID       string
	instanceID      string
	startedAt       time.Time
	heartbeatAt     *time.Time
	lastPrune       time.Time
	now             func() time.Time
}

func New(c config.Config, targets []config.Target, s *store.Store, monitorID string) (*Poller, error) {
	old, err := s.Load(context.Background())
	if err != nil {
		return nil, err
	}
	instance, err := auth.Random()
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Targets are local trusted configuration, never an environment proxy.
	transport.MaxConnsPerHost = concurrency
	transport.MaxIdleConns = concurrency * 2
	transport.MaxIdleConnsPerHost = concurrency
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.TLSHandshakeTimeout = time.Duration(c.TimeoutSeconds) * time.Second
	p := &Poller{config: c, targets: targets, store: s, monitorID: monitorID, instanceID: instance, startedAt: time.Now().UTC(), observations: make(map[string]store.Observation), networkFailures: make(map[string]int), now: time.Now,
		client: &http.Client{Transport: transport, Timeout: time.Duration(c.TimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	ids := make([]string, 0, len(targets))
	for _, t := range targets {
		ids = append(ids, t.ID)
		o := old[t.ID]
		// A reused local id must never expose the previous machine's cache.
		if o.URL != t.URL || o.ExpectedNodeID != t.ExpectedNodeID {
			o = store.Observation{}
		}
		o.ID, o.Name, o.URL, o.ExpectedNodeID = t.ID, t.Name, t.URL, t.ExpectedNodeID
		o.State, o.Stale, o.Failures, o.Message = "unknown", true, 0, "Awaiting a fresh observation"
		p.observations[t.ID] = o
	}
	if err := s.KeepTargets(context.Background(), ids); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Poller) Snapshot() store.Monitor {
	p.mu.RLock()
	defer p.mu.RUnlock()
	now := p.now().UTC()
	m := store.Monitor{APIVersion: "1", MonitorID: p.monitorID, InstanceID: p.instanceID, StartedAt: p.startedAt, HeartbeatAt: p.heartbeatAt, GeneratedAt: now, StaleAfterSeconds: p.config.StaleAfterSeconds, StorageHealthy: p.store.Healthy(), Targets: make([]store.Observation, 0, len(p.targets))}
	for _, t := range p.targets {
		o := p.observations[t.ID]
		o.Stale = o.Stale || o.SucceededAt == nil || now.Sub(*o.SucceededAt) > time.Duration(p.config.StaleAfterSeconds)*time.Second
		m.Targets = append(m.Targets, o)
	}
	return m
}

func (p *Poller) Run(ctx context.Context) {
	defer p.client.CloseIdleConnections()
	ticker := time.NewTicker(time.Duration(p.config.PollIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		p.cycle(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// One bounded worker pool per cycle; cycles cannot overlap. Heartbeat advances
// only after real polling AND persistence/retention work has completed.
func (p *Poller) cycle(ctx context.Context) {
	p.cycleMu.Lock()
	defer p.cycleMu.Unlock()
	jobs := make(chan config.Target)
	var wg sync.WaitGroup
	workers := min(concurrency, len(p.targets))
	for i := 0; i < workers; i++ {
		wg.Go(func() {
			for t := range jobs {
				if ctx.Err() == nil {
					p.poll(ctx, t)
				}
			}
		})
	}
	for _, t := range p.targets {
		select {
		case jobs <- t:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	now := p.now().UTC()
	if p.lastPrune.IsZero() || now.Sub(p.lastPrune) >= time.Hour {
		_ = p.store.Prune(ctx, now.Add(-time.Duration(p.config.RetentionDays)*24*time.Hour))
		p.lastPrune = now
	}
	if ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	now = p.now().UTC()
	p.heartbeatAt = &now
	p.mu.Unlock()
}

func tlsFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	return errors.As(err, &verification) || errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) || errors.As(err, &record) || errors.As(err, &alert)
}

func transportFailure(err error) string {
	var wrapped *url.Error
	if errors.As(err, &wrapped) {
		err = wrapped.Err
	}
	if tlsFailure(err) || strings.HasPrefix(err.Error(), "tls:") || strings.HasPrefix(err.Error(), "remote error: tls:") || strings.Contains(err.Error(), "HTTP response to HTTPS client") {
		return "tls_error"
	}
	var network net.Error
	if errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "network"
	}
	return "protocol_error"
}

func (p *Poller) fetch(ctx context.Context, t config.Target) (*store.Status, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL+"/api/v1/status", nil)
	if err != nil {
		return nil, "protocol_error", "Invalid configured status endpoint"
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		switch transportFailure(err) {
		case "tls_error":
			return nil, "tls_error", "TLS verification or handshake failed"
		case "network":
			return nil, "network", "Status endpoint could not be reached"
		default:
			return nil, "protocol_error", "Status endpoint returned an invalid HTTP response"
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, "auth_error", "Status endpoint rejected authentication"
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "protocol_error", "Status endpoint returned an unexpected HTTP status"
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, "protocol_error", "Status endpoint did not return application/json"
	}
	// Read the actual (possibly decompressed) bytes, not Content-Length.
	body, err := io.ReadAll(io.LimitReader(resp.Body, responseLimit+1))
	if len(body) > responseLimit {
		return nil, "protocol_error", "Status response exceeds 1 MiB"
	}
	if err != nil {
		return nil, transportFailure(err), "Status response could not be read"
	}
	s, err := decodeStatus(body)
	if err != nil {
		return nil, "protocol_error", "Status response failed schema validation"
	}
	if s.NodeID != t.ExpectedNodeID {
		return nil, "identity_mismatch", "Status node identity does not match configured identity"
	}
	return s, "online", "Status received"
}

func (p *Poller) poll(ctx context.Context, t config.Target) {
	status, result, message := p.fetch(ctx, t)
	if ctx.Err() != nil {
		return
	} // Shutdown is not a fabricated outage.
	now := p.now().UTC()
	p.mu.Lock()
	o := p.observations[t.ID]
	previous := o.State
	o.CheckedAt, o.Message = &now, message
	if result == "online" {
		o.State, o.Stale, o.Failures, o.Status, o.SucceededAt = "online", false, 0, status, &now
		p.networkFailures[t.ID] = 0
	} else {
		if o.Failures < 1<<31-1 {
			o.Failures++
		}
		o.Stale = true // Failed attempts always label retained status as cached/stale.
		if result == "network" {
			p.networkFailures[t.ID] = min(p.networkFailures[t.ID]+1, p.config.FailureThreshold)
			if p.networkFailures[t.ID] >= p.config.FailureThreshold {
				o.State = "unreachable"
			}
		} else {
			p.networkFailures[t.ID] = 0
			o.State = result
		}
	}
	var event *store.Event
	if o.State != previous && o.State != "unknown" {
		kind := "error"
		switch o.State {
		case "online":
			if previous != "unknown" {
				kind = "recovered"
			} else {
				kind = ""
			}
		case "unreachable":
			kind = "unreachable"
		}
		if kind != "" {
			event = &store.Event{At: now, TargetID: t.ID, TargetName: t.Name, Kind: kind, State: o.State, Message: message}
		}
	}
	p.observations[t.ID] = o
	p.mu.Unlock()
	// No unbounded in-memory retry queue: a failed transaction is surfaced by
	// storageHealthy and a log, while current in-memory observations stay useful.
	if err := p.store.Save(ctx, o, event); err != nil {
		log.Print("observation persistence failed; event may not be durable")
	}
}
