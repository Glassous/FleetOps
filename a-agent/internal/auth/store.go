package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"fleetops/a-agent/internal/config"
)

const MaxMachineTokens = 256

var (
	ErrStore        = errors.New("authorization state unavailable")
	ErrUnauthorized = errors.New("invalid or expired authentication")
	ErrForbidden    = errors.New("machine token cannot operate on sessions")
	ErrSessionLimit = errors.New("session capacity reached")
)

type MachineToken struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Scope string `json:"scope"`
	Hash  string `json:"hash"`
}

type State struct {
	NodeID             string         `json:"nodeId"`
	CredentialHash     string         `json:"credentialHash"`
	CredentialRevision uint64         `json:"credentialRevision"`
	Tokens             []MachineToken `json:"tokens"`
}

type Identity struct {
	NodeID     string `json:"nodeId"`
	Credential string `json:"credential"`
}

type IssuedToken struct {
	ID    string `json:"id"`
	Token string `json:"token"`
}

type TokenInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Store struct{ Dir string }

func Secret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("secure randomness unavailable")
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func digest(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func matches(hash, value string) bool {
	h := digest(value)
	return subtle.ConstantTimeCompare([]byte(hash), []byte(h)) == 1
}

func validHash(h string) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == sha256.Size && h == strings.ToLower(h)
}

func (s Store) path() string { return filepath.Join(s.Dir, "state.json") }

func checkPermissions(path string, info os.FileInfo, want os.FileMode) error {
	// Windows mode bits do not describe ACLs; retain its platform limitations.
	if runtime.GOOS != "windows" && info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != want {
		return fmt.Errorf("%w: unsafe permissions on %q; set permissions to %04o (chmod %04o) before retrying", ErrStore, path, want, want)
	}
	return nil
}

func (s Store) checkDir() error {
	info, err := os.Stat(s.Dir)
	if err != nil || !info.IsDir() {
		return ErrStore
	}
	return checkPermissions(s.Dir, info, 0700)
}

func (s Store) Read() (State, error) {
	if err := s.checkDir(); err != nil {
		return State{}, err
	}
	f, err := os.Open(s.path())
	if err != nil {
		return State{}, ErrStore
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
		return State{}, ErrStore
	}
	if err := checkPermissions(s.path(), info, 0600); err != nil {
		return State{}, err
	}
	dec := json.NewDecoder(io.LimitReader(f, 2*1024*1024+1))
	dec.DisallowUnknownFields()
	var state State
	if dec.Decode(&state) != nil {
		return State{}, ErrStore
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || state.NodeID == "" || state.CredentialRevision == 0 || !validHash(state.CredentialHash) || len(state.Tokens) > MaxMachineTokens {
		return State{}, ErrStore
	}
	seen := make(map[string]bool)
	for _, t := range state.Tokens {
		if t.ID == "" || seen[t.ID] || !validName(t.Name) || t.Scope != "monitor:read" || !validHash(t.Hash) {
			return State{}, ErrStore
		}
		seen[t.ID] = true
	}
	return state, nil
}

func (s Store) lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return nil, errors.New("cannot create data directory")
	}
	// MkdirAll leaves existing directories unchanged; never chmod user data.
	if err := s.checkDir(); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Dir, "state.lock")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.New("state lock unavailable; inspect existing lock manually")
	}
	return func() { _ = f.Close(); _ = os.Remove(path) }, nil
}

func (s Store) save(state State) error {
	b, err := json.Marshal(state)
	if err != nil {
		return ErrStore
	}
	return config.AtomicWrite(s.path(), append(b, '\n'))
}

func (s Store) Init() (Identity, error) {
	unlock, err := s.lock()
	if err != nil {
		return Identity{}, err
	}
	defer unlock()
	if _, err := os.Lstat(s.path()); err == nil {
		return Identity{}, errors.New("agent already initialized; state was not changed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, ErrStore
	}
	id, err := randomID()
	if err != nil {
		return Identity{}, err
	}
	credential, err := Secret()
	if err != nil {
		return Identity{}, err
	}
	state := State{NodeID: id, CredentialHash: digest(credential), CredentialRevision: 1, Tokens: []MachineToken{}}
	if err := s.save(state); err != nil {
		return Identity{}, err
	}
	return Identity{NodeID: id, Credential: credential}, nil
}

func (s Store) Rotate() (Identity, error) {
	unlock, err := s.lock()
	if err != nil {
		return Identity{}, err
	}
	defer unlock()
	state, err := s.Read()
	if err != nil {
		return Identity{}, err
	}
	if state.CredentialRevision == ^uint64(0) {
		return Identity{}, ErrStore
	}
	credential, err := Secret()
	if err != nil {
		return Identity{}, err
	}
	state.CredentialHash = digest(credential)
	state.CredentialRevision++
	if err := s.save(state); err != nil {
		return Identity{}, err
	}
	return Identity{NodeID: state.NodeID, Credential: credential}, nil
}

func validName(name string) bool {
	return utf8.ValidString(name) && len(name) <= 128 && strings.TrimSpace(name) != "" && !strings.ContainsAny(name, "\r\n\x00")
}

func (s Store) Issue(name string) (IssuedToken, error) {
	if !validName(name) {
		return IssuedToken{}, errors.New("token name must be 1-128 bytes without line breaks")
	}
	unlock, err := s.lock()
	if err != nil {
		return IssuedToken{}, err
	}
	defer unlock()
	state, err := s.Read()
	if err != nil {
		return IssuedToken{}, err
	}
	if len(state.Tokens) >= MaxMachineTokens {
		return IssuedToken{}, errors.New("machine token capacity reached")
	}
	id, err := randomID()
	if err != nil {
		return IssuedToken{}, err
	}
	token, err := Secret()
	if err != nil {
		return IssuedToken{}, err
	}
	state.Tokens = append(state.Tokens, MachineToken{ID: id, Name: name, Scope: "monitor:read", Hash: digest(token)})
	if err := s.save(state); err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{ID: id, Token: token}, nil
}

func (s Store) Revoke(id string) error {
	if id == "" {
		return errors.New("--id is required")
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	state, err := s.Read()
	if err != nil {
		return err
	}
	for i, t := range state.Tokens {
		if t.ID == id {
			state.Tokens = append(state.Tokens[:i], state.Tokens[i+1:]...)
			return s.save(state)
		}
	}
	return errors.New("token not found")
}

func (s Store) List() ([]TokenInfo, error) {
	state, err := s.Read()
	if err != nil {
		return nil, err
	}
	result := make([]TokenInfo, 0, len(state.Tokens))
	for _, t := range state.Tokens {
		result = append(result, TokenInfo{ID: t.ID, Name: t.Name})
	}
	return result, nil
}

// hashEqual always compares fixed-size hashes.
func hashEqual(a, b [sha256.Size]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }
