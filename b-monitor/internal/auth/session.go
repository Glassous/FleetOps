package auth

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrUnauthorized = errors.New("invalid or expired credential")
	ErrLimited      = errors.New("login rate limited or session capacity reached")
	ErrUnavailable  = errors.New("identity state unavailable")
)

const maxSessions = 1024
const maxClients = 2048

type Session struct {
	Token     string    `json:"token,omitempty"`
	NodeID    string    `json:"nodeId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type bucket struct {
	Tokens float64
	At     time.Time
}

type Manager struct {
	mu       sync.Mutex
	dir      string
	state    State
	sessions map[[32]byte]time.Time
	clients  map[string]bucket
	global   bucket
	now      func() time.Time
}

func New(dir string) (*Manager, error) {
	s, err := ReadState(dir)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &Manager{dir: dir, state: s, sessions: make(map[[32]byte]time.Time), clients: make(map[string]bucket), global: bucket{Tokens: 20, At: now}, now: time.Now}, nil
}

// Every authentication rereads the atomically replaced state, so credential
// rotation revokes all sessions before this request can be authorized.
func (m *Manager) refresh(now time.Time) error {
	s, err := ReadState(m.dir)
	if err != nil {
		clear(m.sessions)
		return ErrUnavailable
	}
	if s != m.state {
		clear(m.sessions)
		m.state = s
	}
	for k, expires := range m.sessions {
		if !now.Before(expires) {
			delete(m.sessions, k)
		}
	}
	for k, b := range m.clients {
		if now.Sub(b.At) > 10*time.Minute {
			delete(m.clients, k)
		}
	}
	return nil
}

func take(b bucket, now time.Time, capacity, perSecond float64) (bucket, bool) {
	b.Tokens += now.Sub(b.At).Seconds() * perSecond
	if b.Tokens > capacity {
		b.Tokens = capacity
	}
	b.At = now
	if b.Tokens < 1 {
		return b, false
	}
	b.Tokens--
	return b, true
}

func (m *Manager) Login(credential, client string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.refresh(now); err != nil {
		return Session{}, err
	}
	var allowed bool
	m.global, allowed = take(m.global, now, 20, 1.0/3)
	if !allowed {
		return Session{}, ErrLimited
	}
	b, exists := m.clients[client]
	if !exists {
		if len(m.clients) >= maxClients {
			return Session{}, ErrLimited
		}
		b = bucket{Tokens: 5, At: now}
	}
	b, allowed = take(b, now, 5, 1.0/12)
	m.clients[client] = b
	if !allowed {
		return Session{}, ErrLimited
	}
	expected, _ := hex.DecodeString(m.state.CredentialHash)
	h := Hash(credential)
	if subtle.ConstantTimeCompare(h[:], expected) != 1 {
		return Session{}, ErrUnauthorized
	}
	if len(m.sessions) >= maxSessions {
		return Session{}, ErrLimited
	}
	token, err := Random()
	if err != nil {
		return Session{}, ErrUnavailable
	}
	expires := now.UTC().Add(8 * time.Hour)
	m.sessions[Hash(token)] = expires
	return Session{Token: token, NodeID: m.state.NodeID, ExpiresAt: expires}, nil
}

func (m *Manager) Authenticate(token string, revoke bool) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.refresh(now); err != nil {
		return Session{}, err
	}
	h := Hash(token)
	var expires time.Time
	var found [32]byte
	for key, at := range m.sessions {
		if subtle.ConstantTimeCompare(h[:], key[:]) == 1 {
			expires, found = at, key
		}
	}
	if expires.IsZero() {
		return Session{}, ErrUnauthorized
	}
	if revoke {
		delete(m.sessions, found)
	}
	return Session{NodeID: m.state.NodeID, ExpiresAt: expires}, nil
}
