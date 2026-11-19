package auth

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T) (string, Credential, *Manager) {
	t.Helper()
	dir := t.TempDir()
	c, err := ChangeCredential(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, c, m
}

func TestIdentityRotationAndExpiry(t *testing.T) {
	dir, credential, m := setup(t)
	body, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), credential.Credential) || len(credential.Credential) < 40 {
		t.Fatal("plaintext or weak credential")
	}
	if _, err := ChangeCredential(dir, false); err == nil {
		t.Fatal("reinitialized identity")
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, "identity.json"))
	if string(body) != string(unchanged) {
		t.Fatal("init overwrote identity")
	}
	now := time.Now().UTC()
	m.now = func() time.Time { return now }
	session, err := m.Login(credential.Credential, "local")
	if err != nil || session.ExpiresAt.Sub(now) != 8*time.Hour {
		t.Fatalf("login %v", err)
	}
	identity, err := m.Authenticate(session.Token, false)
	if err != nil || identity.NodeID != credential.NodeID || identity.Token != "" {
		t.Fatal("session identity/token leak")
	}
	if _, err := m.Authenticate(credential.Credential, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("credential accepted as bearer")
	}
	rotated, err := ChangeCredential(dir, true)
	if err != nil || rotated.NodeID != credential.NodeID {
		t.Fatalf("rotation %v", err)
	}
	if _, err := m.Authenticate(session.Token, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("rotation did not revoke session")
	}
	if _, err := m.Login(credential.Credential, "other"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old credential still works")
	}
	session, err = m.Login(rotated.Credential, "new")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(8 * time.Hour)
	if _, err := m.Authenticate(session.Token, false); !errors.Is(err, ErrUnauthorized) || len(m.sessions) != 0 {
		t.Fatal("expiry cleanup failed")
	}
	if runtime.GOOS == "linux" {
		for path, want := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, "identity.json"): 0600} {
			st, err := os.Stat(path)
			if err != nil || st.Mode().Perm() != want {
				t.Errorf("wrong permissions: %s", path)
			}
		}
	}
}

func TestLimitsRevocationAndFailClosed(t *testing.T) {
	dir, c, m := setup(t)
	for i := 0; i < 5; i++ {
		if _, err := m.Login("wrong", "client"); !errors.Is(err, ErrUnauthorized) {
			t.Fatal(err)
		}
	}
	if _, err := m.Login(c.Credential, "client"); !errors.Is(err, ErrLimited) {
		t.Fatal("no login rate limit")
	}
	session, err := m.Login(c.Credential, "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(session.Token, true); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(session.Token, false); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("logout failed")
	}
	now := time.Now()
	for i := 0; i < maxSessions; i++ {
		key := Hash(time.Duration(i).String())
		m.sessions[key] = now.Add(time.Hour)
	}
	if _, err = m.Login(c.Credential, "capacity"); !errors.Is(err, ErrLimited) {
		t.Fatal("unbounded sessions")
	}
	if err := os.Remove(filepath.Join(dir, "identity.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate("anything", false); !errors.Is(err, ErrUnavailable) || len(m.sessions) != 0 {
		t.Fatal("identity read must fail closed")
	}
}

func TestExclusiveLockAndAtomicCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.lock")
	unlock, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := AcquireLock(path); err == nil {
		other()
		t.Fatal("lock not exclusive")
	}
	unlock()
	unlock, err = AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	path = filepath.Join(dir, "state")
	if err := AtomicWrite(path, []byte("original"), false); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("overwrite"), false); err == nil {
		t.Fatal("create overwrote file")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "original" {
		t.Fatal("atomic create violated")
	}
	if err := AtomicWrite(path, []byte("rotated"), true); err != nil {
		t.Fatal(err)
	}
}
