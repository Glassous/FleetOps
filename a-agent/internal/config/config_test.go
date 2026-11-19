package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureDefaultsPathsAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "agent.yaml")
	if err := Ensure(path); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:18080" || c.SampleIntervalSeconds != 5 || c.MetricsScope != "host" || c.DataDir != filepath.Join(filepath.Dir(path), "data") {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if runtime.GOOS != "windows" {
		for p, mode := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("unexpected mode for %s", p)
			}
		}
	}
	custom := []byte("data_dir: elsewhere\nmetrics_scope: container-test\n")
	if err := os.WriteFile(path, custom, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != string(custom) {
		t.Fatal("config was overwritten")
	}
	c, err = Load(path)
	if err != nil || c.DataDir != filepath.Join(filepath.Dir(path), "elsewhere") || c.MetricsScope != "container-test" {
		t.Fatalf("relative data path: %+v %v", c, err)
	}
}

func TestStrictConfiguration(t *testing.T) {
	for _, text := range []string{
		"unknown: SECRET_VALUE\n", "listen: invalid\n", "listen: 127.0.0.1:0\n",
		"sample_interval_seconds: 0\n", "sample_interval_seconds: -1\n", "sample_interval_seconds: 86401\n",
		"metrics_scope: docker\n", "data_dir: ''\n", "listen: 123\n", "[]\n",
		"listen: a\nlisten: b\n", "{}\n---\n{}\n", "allowed_origins: '*'\n",
		"allowed_origins: ['*']\n", "allowed_origins: ['https://a.example/']\n",
		"allowed_origins: ['https://u:p@a.example']\n", "allowed_origins: ['https://a.example?']\n",
	} {
		t.Run(text, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yaml")
			if err := os.WriteFile(path, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil || strings.Contains(err.Error(), "SECRET_VALUE") {
				t.Fatal("expected sanitized config rejection")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("allowed_origins: ['https://web.example', 'http://localhost:3000']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestExistingConfigurationLockIsNotRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path+".lock", []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(path); err == nil {
		t.Fatal("expected lock conflict")
	}
	b, err := os.ReadFile(path + ".lock")
	if err != nil || string(b) != "existing" {
		t.Fatal("existing lock changed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("configuration created despite lock")
	}
}
