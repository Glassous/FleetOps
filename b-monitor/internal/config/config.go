package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen              string   `yaml:"listen"`
	DataDir             string   `yaml:"data_dir"`
	AllowedOrigins      []string `yaml:"allowed_origins"`
	TargetsFile         string   `yaml:"targets_file"`
	PollIntervalSeconds int      `yaml:"poll_interval_seconds"`
	TimeoutSeconds      int      `yaml:"timeout_seconds"`
	FailureThreshold    int      `yaml:"failure_threshold"`
	StaleAfterSeconds   int      `yaml:"stale_after_seconds"`
	RetentionDays       int      `yaml:"retention_days"`
}

type Target struct {
	ID             string `yaml:"id"`
	Name           string `yaml:"name"`
	URL            string `yaml:"url"`
	ExpectedNodeID string `yaml:"expected_node_id"`
	Token          string `yaml:"token"`
}

type Targets struct {
	Targets []Target `yaml:"targets"`
}

func Defaults() Config {
	return Config{Listen: "127.0.0.1:18081", DataDir: "data", AllowedOrigins: []string{}, TargetsFile: "targets.yaml", PollIntervalSeconds: 30, TimeoutSeconds: 5, FailureThreshold: 3, StaleAfterSeconds: 90, RetentionDays: 30}
}

func decode(path string, into any, private bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	// Check the decoded file descriptor; Windows mode bits do not describe ACLs.
	if private && (!info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode() != 0600)) {
		return errors.New("targets configuration must be a regular file with mode 0600")
	}
	if info.Size() > 1<<20 {
		return errors.New("configuration exceeds 1 MiB")
	}
	d := yaml.NewDecoder(io.LimitReader(f, (1<<20)+1))
	d.KnownFields(true)
	if err := d.Decode(into); err != nil {
		return errors.New("invalid configuration YAML")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("configuration must contain one document")
	}
	return nil
}

func Load(path string) (Config, error) {
	c := Defaults()
	if err := decode(path, &c, false); err != nil {
		return c, err
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return c, errors.New("listen must be host:port")
	}
	if c.DataDir == "" || c.TargetsFile == "" {
		return c, errors.New("data_dir and targets_file must not be empty")
	}
	if c.PollIntervalSeconds < 1 || c.PollIntervalSeconds > 86400 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 3600 || c.FailureThreshold < 1 || c.FailureThreshold > 10000 || c.StaleAfterSeconds < 1 || c.StaleAfterSeconds > 31536000 || c.RetentionDays < 1 || c.RetentionDays > 36500 {
		return c, errors.New("configuration interval, timeout, threshold or retention out of range")
	}
	seen := map[string]bool{}
	for _, origin := range c.AllowedOrigins {
		normalized, err := NormalizeOrigin(origin)
		if err != nil || normalized != origin || seen[origin] {
			return c, errors.New("allowed_origins must contain unique canonical HTTP(S) origins")
		}
		seen[origin] = true
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return c, err
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(filepath.Dir(abs), c.DataDir)
	}
	if !filepath.IsAbs(c.TargetsFile) {
		c.TargetsFile = filepath.Join(filepath.Dir(abs), c.TargetsFile)
	}
	return c, nil
}

// NormalizeOrigin rejects URL components which could change the fixed status endpoint.
func NormalizeOrigin(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u == nil {
		return "", errors.New("invalid HTTP(S) origin")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.Opaque != "" {
		return "", errors.New("URL must be an HTTP(S) origin without credentials, query, fragment or path")
	}
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, "\\% \t\r\n") {
		return "", errors.New("invalid origin host")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("empty origin port")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid origin port")
		}
		port = strconv.Itoa(n)
	}
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host, nil
}

func LoadTargets(path string) ([]Target, error) {
	var file Targets
	if err := decode(path, &file, true); err != nil {
		return nil, err
	}
	if len(file.Targets) > 10000 {
		return nil, errors.New("too many targets (maximum 10000)")
	}
	ids := map[string]bool{}
	for i := range file.Targets {
		t := &file.Targets[i]
		if strings.TrimSpace(t.ID) == "" || ids[t.ID] || strings.TrimSpace(t.Name) == "" || strings.TrimSpace(t.ExpectedNodeID) == "" || strings.TrimSpace(t.Token) == "" || strings.ContainsAny(t.Token, "\r\n") {
			return nil, fmt.Errorf("target %d: duplicate id or invalid required field", i+1)
		}
		ids[t.ID] = true
		u, err := NormalizeOrigin(t.URL)
		if err != nil {
			return nil, fmt.Errorf("target %d: invalid origin", i+1)
		}
		t.URL = u
	}
	if file.Targets == nil {
		file.Targets = []Target{}
	}
	return file.Targets, nil
}
