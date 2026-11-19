package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func file(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(file(t, dir, "config.yaml", "{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:18081" || c.PollIntervalSeconds != 30 || c.TimeoutSeconds != 5 || c.FailureThreshold != 3 || c.StaleAfterSeconds != 90 || c.RetentionDays != 30 {
		t.Fatalf("wrong defaults: %+v", c)
	}
	if c.DataDir != filepath.Join(dir, "data") || c.TargetsFile != filepath.Join(dir, "targets.yaml") {
		t.Fatal("paths not relative to config")
	}
	targets, err := LoadTargets(file(t, dir, "targets.yaml", "targets: []\n"))
	if err != nil || targets == nil || len(targets) != 0 {
		t.Fatalf("empty targets: %v", err)
	}
}

func TestOriginValidation(t *testing.T) {
	for input, expected := range map[string]string{"http://EXAMPLE.com:80/": "http://example.com", "https://example.com:443": "https://example.com", "http://[::1]:18080/": "http://[::1]:18080", "http://example.com:0081": "http://example.com:81"} {
		got, err := NormalizeOrigin(input)
		if err != nil || got != expected {
			t.Errorf("%s: %s %v", input, got, err)
		}
	}
	for _, input := range []string{"ftp://host", "http://user:secret@host", "http://host/x", "http://host?x", "http://host?", "http://host#", "http://host#x", "http://host/%2f", "http://host:0", "http://host:65536", "http://host:", "//host", "http:///", "http://host\\other"} {
		if _, err := NormalizeOrigin(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestStrictConfigAndTargets(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"poll_interval_seconds: 0", "timeout_seconds: -1", "failure_threshold: 0", "stale_after_seconds: 0", "retention_days: 0", "listen: bad", "unknown: 1", "allowed_origins: ['*']", "allowed_origins: ['https://example.com/']", "allowed_origins: ['https://example.com', 'https://example.com']", "{}\n---\n{}"} {
		if _, err := Load(file(t, dir, "config.yaml", body)); err == nil {
			t.Errorf("accepted config %q", body)
		}
	}
	valid := "targets:\n  - {id: one, name: First, url: 'http://EXAMPLE.com:80/', expected_node_id: node, token: secret}\n"
	ts, err := LoadTargets(file(t, dir, "targets.yaml", valid))
	if err != nil || len(ts) != 1 || ts[0].URL != "http://example.com" {
		t.Fatalf("valid targets: %v", err)
	}
	for _, body := range []string{valid + "  - {id: one, name: Duplicate, url: 'http://host', expected_node_id: n, token: s}\n", strings.Replace(valid, "name: First", "name: ''", 1), strings.Replace(valid, "expected_node_id: node", "expected_node_id: ''", 1), strings.Replace(valid, "token: secret", "token: ''", 1), strings.Replace(valid, "token: secret", "token: [secret]", 1), strings.Replace(valid, "token: secret", "token: secret, unexpected: true", 1), strings.Replace(valid, "http://EXAMPLE.com:80/", "http://secret@host", 1)} {
		if _, err := LoadTargets(file(t, dir, "targets.yaml", body)); err == nil {
			t.Errorf("accepted malformed targets")
		} else if strings.Contains(err.Error(), "secret") {
			t.Error("target error disclosed a secret")
		}
	}
}

func TestTargetsFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix file permissions")
	}
	const secret = "permission-test-token"
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{"0600", 0600},
		{"0400", 0400},
		{"0640", 0640},
		{"0644", 0644},
		{"0666", 0666},
		{"0700", 0700},
		{"setuid", os.ModeSetuid | 0600},
		{"setgid", os.ModeSetgid | 0600},
		{"sticky", os.ModeSticky | 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := file(t, t.TempDir(), "targets.yaml", "targets:\n  - {id: one, name: First, url: 'http://host', expected_node_id: node, token: "+secret+"}\n")
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			targets, err := LoadTargets(path)
			if tc.mode == 0600 {
				if err != nil || len(targets) != 1 || targets[0].Token != secret {
					t.Fatal("valid private targets file was not loaded")
				}
			} else {
				if err == nil || targets != nil {
					t.Fatal("accepted targets file without mode 0600")
				}
				if !strings.Contains(err.Error(), "0600") || strings.Contains(err.Error(), secret) {
					t.Fatal("permission error must explain the mode without disclosing the token")
				}
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode() != tc.mode {
				t.Fatalf("loading changed the existing mode: got %v, want %v", info.Mode(), tc.mode)
			}
		})
	}
}

func TestTargetsRequireRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file-type checks")
	}
	for _, path := range []string{t.TempDir(), os.DevNull} {
		if targets, err := LoadTargets(path); err == nil || targets != nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("non-regular file was not rejected before decoding: %v", err)
		}
	}
}

func TestConfigPermissionsUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix file permissions")
	}
	path := file(t, t.TempDir(), "config.yaml", "{}\n")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("ordinary configuration must still accept mode 0644: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatal("loading changed ordinary configuration permissions")
	}
}
