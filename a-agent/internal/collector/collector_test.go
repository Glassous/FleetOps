package collector

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

func fakeCollector() *Collector {
	c := New("node-test", "container-test", time.Now().Add(-time.Minute))
	calls := 0
	c.read = readers{
		info: func(context.Context) (*host.InfoStat, error) {
			return &host.InfoStat{Hostname: "test-host", OS: "linux", Platform: "debian", KernelVersion: "6.1", Uptime: 98765}, nil
		},
		counts: func(context.Context, bool) (int, error) { return 4, nil },
		times: func(context.Context, bool) ([]cpu.TimesStat, error) {
			calls++
			return []cpu.TimesStat{{User: float64(20 * calls), Idle: float64(80 * calls), Guest: float64(10 * calls)}}, nil
		},
		memory: func(context.Context) (*mem.VirtualMemoryStat, error) {
			return &mem.VirtualMemoryStat{Total: 1000, Used: 250, UsedPercent: 25}, nil
		},
		disk: func(context.Context, string) (*disk.UsageStat, error) {
			return &disk.UsageStat{Total: 2000, Used: 1000, UsedPercent: 50}, nil
		},
	}
	return c
}

func TestSamplesContractCPUAndCache(t *testing.T) {
	c := fakeCollector()
	if _, ready := c.Status(); ready {
		t.Fatal("sample ready before collection")
	}
	if err := c.Sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, ready := c.Status()
	if !ready || s.CPU.UsagePercent != nil || s.Memory == nil || s.Disk == nil {
		t.Fatal("first sample must have null CPU and real usage")
	}
	if s.APIVersion != "1" || s.AgentVersion != "0.1.0" || s.NodeID != "node-test" || s.MetricsScope != "container-test" || s.CPU.LogicalCount != 4 || s.UptimeSeconds != 98765 || s.System.Arch != runtime.GOARCH {
		t.Fatalf("incorrect sample: %+v", s)
	}
	if s.SampledAt.IsZero() || !s.AgentStartedAt.Before(s.SampledAt) {
		t.Fatal("invalid timestamps")
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, field := range []string{"apiVersion", "nodeId", "hostname", "system", "agentVersion", "metricsScope", "sampledAt", "agentStartedAt", "uptimeSeconds", "cpu", "memory", "disk"} {
		if _, ok := fields[field]; !ok {
			t.Fatalf("missing %s", field)
		}
	}
	if len(fields) != 12 {
		t.Fatalf("unexpected fields: %s", b)
	}
	if err := c.Sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ = c.Status()
	if s.CPU.UsagePercent == nil || math.Abs(*s.CPU.UsagePercent-20) > 0.0001 {
		t.Fatalf("incorrect CPU delta: %+v", s.CPU)
	}
	stamp := s.SampledAt
	*s.CPU.UsagePercent = 99
	s.Memory.UsedBytes = 999
	cached, _ := c.Status()
	if !cached.SampledAt.Equal(stamp) || *cached.CPU.UsagePercent != 20 || cached.Memory.UsedBytes != 250 {
		t.Fatal("cache mutated or resampled per request")
	}
}

func TestMissingAndInvalidMetricsAreNull(t *testing.T) {
	c := fakeCollector()
	fail := errors.New("unavailable")
	c.read.memory = func(context.Context) (*mem.VirtualMemoryStat, error) { return nil, fail }
	c.read.disk = func(context.Context, string) (*disk.UsageStat, error) { return nil, fail }
	c.read.times = func(context.Context, bool) ([]cpu.TimesStat, error) { return nil, fail }
	if err := c.Sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ := c.Status()
	if s.Memory != nil || s.Disk != nil || s.CPU.UsagePercent != nil {
		t.Fatal("missing metrics were invented")
	}
	b, _ := json.Marshal(s)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if string(fields["memory"]) != "null" || string(fields["disk"]) != "null" {
		t.Fatal("missing metrics omitted instead of null")
	}
	c.read.info = func(context.Context) (*host.InfoStat, error) { return nil, fail }
	if err := c.Sample(context.Background()); err == nil {
		t.Fatal("core failure hidden")
	}
	cached, ready := c.Status()
	if !ready || !cached.SampledAt.Equal(s.SampledAt) {
		t.Fatal("failed sample replaced previous cache")
	}
	for _, value := range []float64{-1, 101, math.NaN(), math.Inf(1)} {
		if usage(100, 10, value) != nil {
			t.Fatal("invalid usage accepted")
		}
	}
	if usage(0, 0, 0) != nil || usage(1, 2, 50) != nil {
		t.Fatal("invalid bytes accepted")
	}
}

func TestCPUNoDeltaResetAndRoot(t *testing.T) {
	previous := &cpu.TimesStat{User: 20, Idle: 80}
	for _, current := range []*cpu.TimesStat{nil, previous, {User: 10, Idle: 10}, {User: math.NaN(), Idle: 100}} {
		if cpuPercent(previous, current) != nil {
			t.Fatal("invalid CPU delta should be null")
		}
	}
	root, err := rootPath()
	if err != nil || !filepath.IsAbs(root) {
		t.Fatalf("invalid root: %q %v", root, err)
	}
	if runtime.GOOS != "windows" && root != "/" {
		t.Fatal("Linux must use root filesystem")
	}
}

func TestCancelledInitialSampleDoesNotCreateCPUHistory(t *testing.T) {
	c := fakeCollector()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Sample(ctx); err == nil {
		t.Fatal("cancelled sample succeeded")
	}
	if _, ready := c.Status(); ready {
		t.Fatal("cancelled sample published")
	}
	if err := c.Sample(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, ready := c.Status()
	if !ready || s.CPU.UsagePercent != nil {
		t.Fatal("first published sample must have null CPU")
	}
	done := make(chan struct{})
	go func() { c.Run(ctx, time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector ignored cancellation")
	}
}

func TestRealPlatformCollection(t *testing.T) {
	c := New("local-smoke", "host", time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	s, ready := c.Status()
	if !ready || s.Hostname == "" || s.System.OS != runtime.GOOS || s.System.Kernel == "" || s.CPU.LogicalCount < 1 || s.CPU.UsagePercent != nil {
		t.Fatalf("invalid real sample: %+v", s)
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatal(err)
	}
}
