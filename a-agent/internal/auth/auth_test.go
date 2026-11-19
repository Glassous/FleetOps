package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func setup(t *testing.T) (Store, Identity) {
	t.Helper()
	s := Store{Dir: filepath.Join(t.TempDir(), "data")}
	i, err := s.Init()
	if err != nil {
		t.Fatal(err)
	}
	return s, i
}

func TestInitPersistenceNoOverwriteAndPermissions(t *testing.T) {
	s, identity := setup(t)
	secret, err := base64.RawURLEncoding.DecodeString(identity.Credential)
	if err != nil || len(secret) != 32 || identity.NodeID == "" {
		t.Fatal("invalid generated identity")
	}
	before, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), identity.Credential) || !strings.Contains(string(before), digest(identity.Credential)) {
		t.Fatal("plaintext credential persisted or hash missing")
	}
	if _, err := s.Init(); err == nil {
		t.Fatal("second init succeeded")
	}
	after, _ := os.ReadFile(s.path())
	if string(before) != string(after) {
		t.Fatal("second init modified state")
	}
	state, err := (Store{Dir: s.Dir}).Read()
	if err != nil || state.NodeID != identity.NodeID || state.CredentialRevision != 1 {
		t.Fatal("identity not persistent")
	}
	if runtime.GOOS != "windows" {
		for p, mode := range map[string]os.FileMode{s.Dir: 0700, s.path(): 0600} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("unexpected mode: %s", p)
			}
		}
	}
}

func TestInitExistingDirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not enforce Unix permissions")
	}
	for _, mode := range []os.FileMode{0700, 0755} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			s := Store{Dir: filepath.Join(t.TempDir(), "data")}
			if err := os.Mkdir(s.Dir, mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(s.Dir, mode); err != nil {
				t.Fatal(err)
			}
			_, err := s.Init()
			if mode == 0700 {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.Read(); err != nil {
					t.Fatal(err)
				}
			} else {
				if !errors.Is(err, ErrStore) || !strings.Contains(err.Error(), "chmod 0700") || !strings.Contains(err.Error(), s.Dir) {
					t.Fatalf("expected directory permission repair guidance, got %v", err)
				}
				entries, err := os.ReadDir(s.Dir)
				if err != nil || len(entries) != 0 {
					t.Fatal("rejected init created state or lock files")
				}
			}
			info, err := os.Stat(s.Dir)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatal("init changed existing directory permissions")
			}
		})
	}
}

func TestUnsafeStatePermissionsFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows mode bits do not enforce Unix permissions")
	}
	for _, directory := range []bool{true, false} {
		name := "state_0644"
		if directory {
			name = "directory_0755"
		}
		t.Run(name, func(t *testing.T) {
			s, identity := setup(t)
			m := NewManager(s)
			session, err := m.Login(identity.Credential)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(s.path())
			if err != nil {
				t.Fatal(err)
			}
			path, unsafeMode, safeMode := s.path(), os.FileMode(0644), os.FileMode(0600)
			if directory {
				path, unsafeMode, safeMode = s.Dir, 0755, 0700
			}
			if err := os.Chmod(path, unsafeMode); err != nil {
				t.Fatal(err)
			}
			for name, op := range map[string]func() error{
				"read":         func() error { _, err := s.Read(); return err },
				"rotate":       func() error { _, err := s.Rotate(); return err },
				"issue":        func() error { _, err := s.Issue("test"); return err },
				"revoke":       func() error { return s.Revoke("test") },
				"login":        func() error { _, err := m.Login(identity.Credential); return err },
				"authenticate": func() error { _, err := m.Authenticate(session.Token, false); return err },
				"logout":       func() error { return m.Logout(session.Token) },
			} {
				if err := op(); !errors.Is(err, ErrStore) || !strings.Contains(err.Error(), fmt.Sprintf("chmod %04o", safeMode)) || !strings.Contains(err.Error(), path) {
					t.Fatalf("%s: expected permission repair guidance, got %v", name, err)
				}
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != unsafeMode {
				t.Fatal("existing permissions changed automatically")
			}
			after, err := os.ReadFile(s.path())
			if err != nil || string(before) != string(after) {
				t.Fatal("rejected operations modified state")
			}
			if _, err := os.Stat(filepath.Join(s.Dir, "state.lock")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected operation left a state lock")
			}
			if err := os.Chmod(path, safeMode); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Authenticate(session.Token, false); err != nil {
				t.Fatalf("session unusable after manual permission repair: %v", err)
			}
		})
	}
}

func TestLoginExpiryLogoutAndRotation(t *testing.T) {
	s, identity := setup(t)
	m := NewManager(s)
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return now }
	if _, err := m.Login("wrong-secret"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("wrong credential accepted")
	}
	session, err := m.Login(identity.Credential)
	if err != nil || session.NodeID != identity.NodeID || !session.ExpiresAt.Equal(now.Add(8*time.Hour)) {
		t.Fatalf("login: %v", err)
	}
	if _, err := m.Authenticate(identity.Credential, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("credential used as bearer")
	}
	if _, err := m.Authenticate(session.Token, false); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(s).Authenticate(session.Token, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("session survived restart")
	}
	now = session.ExpiresAt
	if _, err := m.Authenticate(session.Token, false); !errors.Is(err, ErrUnauthorized) || len(m.sessions) != 0 {
		t.Fatal("expired session not cleaned")
	}
	session, _ = m.Login(identity.Credential)
	if err := m.Logout(session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(session.Token, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("logout ineffective")
	}
	if err := m.Logout(session.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("double logout should fail")
	}
	old, _ := m.Login(identity.Credential)
	rotated, err := s.Rotate()
	if err != nil || rotated.NodeID != identity.NodeID || rotated.Credential == identity.Credential {
		t.Fatalf("rotation: %v", err)
	}
	if _, err := m.Authenticate(old.Token, false); !errors.Is(err, ErrUnauthorized) || len(m.sessions) != 0 {
		t.Fatal("rotation did not invalidate sessions")
	}
	if _, err := m.Login(identity.Credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old credential accepted")
	}
	if _, err := m.Login(rotated.Credential); err != nil {
		t.Fatal(err)
	}
}

func TestMachineTokenScopeListHashAndLiveRevocation(t *testing.T) {
	s, identity := setup(t)
	m := NewManager(s)
	token, err := s.Issue("巡检")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := base64.RawURLEncoding.DecodeString(token.Token)
	if len(b) != 32 {
		t.Fatal("token entropy length")
	}
	state, err := os.ReadFile(s.path())
	if err != nil || strings.Contains(string(state), token.Token) || !strings.Contains(string(state), digest(token.Token)) {
		t.Fatal("token not hash-only")
	}
	list, err := s.List()
	if err != nil || len(list) != 1 || list[0].ID != token.ID || list[0].Name != "巡检" {
		t.Fatalf("list: %v", err)
	}
	encoded, _ := json.Marshal(list)
	var fields []map[string]any
	_ = json.Unmarshal(encoded, &fields)
	if len(fields[0]) != 2 {
		t.Fatal("list exposes extra token fields")
	}
	p, err := m.Authenticate(token.Token, true)
	if err != nil || !p.Machine || p.NodeID != identity.NodeID {
		t.Fatalf("status token: %v", err)
	}
	if _, err := m.Authenticate(token.Token, false); !errors.Is(err, ErrForbidden) {
		t.Fatal("machine token may access session")
	}
	if err := m.Logout(token.Token); !errors.Is(err, ErrForbidden) {
		t.Fatal("machine token may logout")
	}
	if _, err := m.Login(token.Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("machine token used as credential")
	}
	if _, err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(token.Token, true); err != nil {
		t.Fatal("credential rotation unexpectedly revoked machine token")
	}
	if err := s.Revoke(token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(token.Token, true); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("live revocation ineffective")
	}
	list, err = s.List()
	if err != nil || len(list) != 0 {
		t.Fatal("revoked token still listed")
	}
}

func TestStateLockConflictDoesNotDeleteExistingLock(t *testing.T) {
	s, _ := setup(t)
	path := filepath.Join(s.Dir, "state.lock")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, op := range []func() error{
		func() error { _, err := s.Init(); return err },
		func() error { _, err := s.Rotate(); return err },
		func() error { _, err := s.Issue("test"); return err },
		func() error { return s.Revoke("test") },
	} {
		if err := op(); err == nil {
			t.Fatal("lock conflict ignored")
		}
		b, err := os.ReadFile(path)
		if err != nil || string(b) != "existing" {
			t.Fatal("existing lock removed")
		}
	}
	if _, err := s.Read(); err != nil {
		t.Fatal("read blocked by write lock")
	}
}

func TestBoundedSessionsAndFailClosed(t *testing.T) {
	s, identity := setup(t)
	m := NewManager(s)
	now := time.Now()
	m.now = func() time.Time { return now }
	for i := 0; i < MaxSessions; i++ {
		key := sha256.Sum256(fmt.Appendf(nil, "%d", i))
		m.sessions[key] = sessionEntry{nodeID: identity.NodeID, expires: now.Add(time.Hour), revision: 1}
	}
	if _, err := m.Login(identity.Credential); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("session limit ignored")
	}
	now = now.Add(time.Hour)
	session, err := m.Login(identity.Credential)
	if err != nil || len(m.sessions) != 1 {
		t.Fatal("expired sessions did not free capacity")
	}
	if err := os.WriteFile(s.path(), []byte(`{"credentialHash":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(session.Token, true); !errors.Is(err, ErrStore) {
		t.Fatal("corrupt state did not fail closed")
	}
	if _, err := m.Login(identity.Credential); !errors.Is(err, ErrStore) {
		t.Fatal("login ignored corrupt state")
	}
}

func TestConcurrentInitOnlyOneSucceeds(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "data")}
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Init(); results <- err }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful initializations: %d", successes)
	}
	if _, err := s.Read(); err != nil {
		t.Fatal(err)
	}
}
