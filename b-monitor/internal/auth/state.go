package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type State struct {
	NodeID         string `json:"nodeId"`
	CredentialHash string `json:"credentialHash"`
}

type Credential struct {
	NodeID     string `json:"nodeId"`
	Credential string `json:"credential"`
}

func Random() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func Hash(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.Chmod(dir, 0700)
}

// AtomicWrite never exposes a partially written secret/state file. For initial
// creation, a hard link gives atomic create-if-absent rather than overwriting.
func AtomicWrite(path string, data []byte, replace bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".fleetops-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if replace {
		err = os.Rename(tmp, path)
	} else {
		err = os.Link(tmp, path)
	}
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer d.Close()
		return d.Sync()
	}
	return nil
}

func ReadState(dir string) (State, error) {
	var s State
	f, err := os.Open(filepath.Join(dir, "identity.json"))
	if err != nil {
		return s, errors.New("identity unavailable; run init first")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 4096 {
		return s, errors.New("invalid identity state")
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, errors.New("invalid identity state")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return s, errors.New("invalid identity state")
	}
	h, err := hex.DecodeString(s.CredentialHash)
	if s.NodeID == "" || err != nil || len(h) != 32 {
		return s, errors.New("invalid identity state")
	}
	return s, nil
}

func ChangeCredential(dir string, rotate bool) (Credential, error) {
	var out Credential
	if err := SecureDir(dir); err != nil {
		return out, err
	}
	unlock, err := AcquireLock(filepath.Join(dir, "cli.lock"))
	if err != nil {
		return out, err
	}
	defer unlock()
	path := filepath.Join(dir, "identity.json")
	var state State
	if rotate {
		state, err = ReadState(dir)
		if err != nil {
			return out, err
		}
	} else {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return out, errors.New("already initialized; identity will not be overwritten")
		}
		state.NodeID, err = Random()
		if err != nil {
			return out, err
		}
	}
	secret, err := Random()
	if err != nil {
		return out, err
	}
	h := Hash(secret)
	state.CredentialHash = hex.EncodeToString(h[:])
	data, err := json.Marshal(state)
	if err != nil {
		return out, err
	}
	if err := AtomicWrite(path, append(data, '\n'), rotate); err != nil {
		return out, err
	}
	return Credential{NodeID: state.NodeID, Credential: secret}, nil
}
