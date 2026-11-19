package auth

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

const (
	SessionTTL  = 8 * time.Hour
	MaxSessions = 1024
)

type Session struct {
	Token     string    `json:"token"`
	NodeID    string    `json:"nodeId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Principal struct {
	NodeID    string    `json:"nodeId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Machine   bool      `json:"-"`
}

type sessionEntry struct {
	nodeID   string
	expires  time.Time
	revision uint64
}

type Manager struct {
	store    Store
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]sessionEntry
	now      func() time.Time
}

func NewManager(store Store) *Manager {
	return &Manager{store: store, sessions: make(map[[sha256.Size]byte]sessionEntry), now: time.Now}
}

func (m *Manager) prune(now time.Time, state *State) {
	for key, entry := range m.sessions {
		if !now.Before(entry.expires) || (state != nil && (entry.revision != state.CredentialRevision || entry.nodeID != state.NodeID)) {
			delete(m.sessions, key)
		}
	}
}

func (m *Manager) RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			m.prune(m.now(), nil)
			m.mu.Unlock()
		}
	}
}

func (m *Manager) Login(credential string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.store.Read()
	if err != nil {
		return Session{}, err
	}
	now := m.now().UTC()
	m.prune(now, &state)
	if len(credential) == 0 || len(credential) > 512 || !matches(state.CredentialHash, credential) {
		return Session{}, ErrUnauthorized
	}
	if len(m.sessions) >= MaxSessions {
		return Session{}, ErrSessionLimit
	}
	token, err := Secret()
	if err != nil {
		return Session{}, ErrStore
	}
	expires := now.Add(SessionTTL)
	m.sessions[sha256.Sum256([]byte(token))] = sessionEntry{nodeID: state.NodeID, expires: expires, revision: state.CredentialRevision}
	return Session{Token: token, NodeID: state.NodeID, ExpiresAt: expires}, nil
}

// Every authentication loads the atomically published state. Revocation and
// credential rotation therefore take effect on the next request, without restart.
func (m *Manager) Authenticate(token string, allowMachine bool) (Principal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authenticate(token, allowMachine, false)
}

func (m *Manager) authenticate(token string, allowMachine, revoke bool) (Principal, error) {
	if len(token) == 0 || len(token) > 512 {
		return Principal{}, ErrUnauthorized
	}
	state, err := m.store.Read()
	if err != nil {
		return Principal{}, err
	}
	now := m.now()
	m.prune(now, &state)
	key := sha256.Sum256([]byte(token))
	var found *sessionEntry
	var foundKey [sha256.Size]byte
	for candidate, entry := range m.sessions {
		if hashEqual(candidate, key) {
			copy := entry
			found = &copy
			foundKey = candidate
		}
	}
	if found != nil {
		if revoke {
			delete(m.sessions, foundKey)
		}
		return Principal{NodeID: found.nodeID, ExpiresAt: found.expires}, nil
	}
	machine := false
	for _, t := range state.Tokens {
		if matches(t.Hash, token) && t.Scope == "monitor:read" {
			machine = true
		}
	}
	if machine {
		if !allowMachine {
			return Principal{}, ErrForbidden
		}
		return Principal{NodeID: state.NodeID, Machine: true}, nil
	}
	return Principal{}, ErrUnauthorized
}

func (m *Manager) Logout(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.authenticate(token, false, true)
	return err
}
