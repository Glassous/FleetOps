package config

import (
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultYAML = "listen: 127.0.0.1:18080\ndata_dir: data\nallowed_origins: []\nsample_interval_seconds: 5\nmetrics_scope: host\n"

var ErrInvalid = errors.New("invalid configuration")

type Config struct {
	Listen                string   `yaml:"listen"`
	DataDir               string   `yaml:"data_dir"`
	AllowedOrigins        []string `yaml:"allowed_origins"`
	SampleIntervalSeconds int      `yaml:"sample_interval_seconds"`
	MetricsScope          string   `yaml:"metrics_scope"`
}

// Resolve makes --config absolute once; all paths inside it use its directory,
// never the service's working directory.
func Resolve(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--config is required")
	}
	p, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalid
	}
	return filepath.Clean(p), nil
}

func Load(path string) (Config, error) {
	c := Config{Listen: "127.0.0.1:18080", DataDir: "data", SampleIntervalSeconds: 5, MetricsScope: "host"}
	p, err := Resolve(path)
	if err != nil {
		return Config{}, err
	}
	f, err := os.Open(p)
	if err != nil {
		return Config{}, errors.New("cannot read configuration")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32*1024 {
		return Config{}, ErrInvalid
	}
	dec := yaml.NewDecoder(io.LimitReader(f, 32*1024+1))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, ErrInvalid
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Config{}, ErrInvalid
	}
	h, port, err := net.SplitHostPort(c.Listen)
	if err != nil || (h != "" && h != "localhost" && net.ParseIP(h) == nil) {
		return Config{}, ErrInvalid
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || c.DataDir == "" || c.SampleIntervalSeconds < 1 || c.SampleIntervalSeconds > 86400 {
		return Config{}, ErrInvalid
	}
	if c.MetricsScope != "host" && c.MetricsScope != "container-test" {
		return Config{}, ErrInvalid
	}
	for _, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || strings.ContainsAny(origin, "\r\n\t ") {
			return Config{}, ErrInvalid
		}
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(filepath.Dir(p), c.DataDir)
	}
	c.DataDir = filepath.Clean(c.DataDir)
	return c, nil
}

// Ensure only creates a missing configuration. An exclusive sibling lock protects
// concurrent init calls; an existing lock is never automatically removed.
func Ensure(path string) error {
	p, err := Resolve(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return errors.New("cannot create configuration directory")
	}
	lock, err := os.OpenFile(p+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("configuration lock unavailable; inspect existing lock manually")
	}
	defer func() { _ = lock.Close(); _ = os.Remove(p + ".lock") }()
	if _, err := os.Lstat(p); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect configuration")
	}
	return AtomicWrite(p, []byte(DefaultYAML))
}

// AtomicWrite publishes only a complete, fsynced 0600 file in the same directory.
// Callers serialize mutations using an exclusive lock.
func AtomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".fleetops-*")
	if err != nil {
		return errors.New("cannot create persistent file")
	}
	defer os.Remove(f.Name())
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	if _, err = f.Write(data); err != nil {
		return errors.New("cannot write persistent file")
	}
	if err = f.Sync(); err != nil {
		return errors.New("cannot sync persistent file")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close persistent file")
	}
	ok = true
	if err = os.Rename(f.Name(), path); err != nil {
		return errors.New("cannot publish persistent file")
	}
	return nil
}
