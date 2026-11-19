package collector

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

const Version = "0.1.0"

type Usage struct {
	TotalBytes  uint64  `json:"totalBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
}

type System struct {
	OS       string `json:"os"`
	Platform string `json:"platform"`
	Kernel   string `json:"kernel"`
	Arch     string `json:"arch"`
}

type CPU struct {
	LogicalCount int      `json:"logicalCount"`
	UsagePercent *float64 `json:"usagePercent"`
}

type Status struct {
	APIVersion     string    `json:"apiVersion"`
	NodeID         string    `json:"nodeId"`
	Hostname       string    `json:"hostname"`
	System         System    `json:"system"`
	AgentVersion   string    `json:"agentVersion"`
	MetricsScope   string    `json:"metricsScope"`
	SampledAt      time.Time `json:"sampledAt"`
	AgentStartedAt time.Time `json:"agentStartedAt"`
	UptimeSeconds  uint64    `json:"uptimeSeconds"`
	CPU            CPU       `json:"cpu"`
	Memory         *Usage    `json:"memory"`
	Disk           *Usage    `json:"disk"`
}

type readers struct {
	info   func(context.Context) (*host.InfoStat, error)
	counts func(context.Context, bool) (int, error)
	times  func(context.Context, bool) ([]cpu.TimesStat, error)
	memory func(context.Context) (*mem.VirtualMemoryStat, error)
	disk   func(context.Context, string) (*disk.UsageStat, error)
}

type Collector struct {
	mu            sync.RWMutex
	sampleMu      sync.Mutex
	cached        Status
	ready         bool
	previous      *cpu.TimesStat
	read          readers
	nodeID, scope string
	started       time.Time
}

func New(nodeID, scope string, started time.Time) *Collector {
	return &Collector{nodeID: nodeID, scope: scope, started: started.UTC(), read: readers{
		info: host.InfoWithContext, counts: cpu.CountsWithContext,
		times: cpu.TimesWithContext, memory: mem.VirtualMemoryWithContext, disk: disk.UsageWithContext,
	}}
}

func rootPath() (string, error) {
	if runtime.GOOS != "windows" {
		return "/", nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.VolumeName(cwd) + string(filepath.Separator), nil
}

func total(t cpu.TimesStat) float64 {
	// Linux guest counters are already included in user/nice.
	return t.User + t.Nice + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
}

func cpuPercent(previous, current *cpu.TimesStat) *float64 {
	if previous == nil || current == nil {
		return nil
	}
	delta := total(*current) - total(*previous)
	idle := (current.Idle + current.Iowait) - (previous.Idle + previous.Iowait)
	if delta <= 0 || idle < 0 || idle > delta || math.IsNaN(delta) || math.IsInf(delta, 0) {
		return nil
	}
	value := 100 * (delta - idle) / delta
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil
	}
	value = math.Max(0, math.Min(100, value))
	return &value
}

func usage(total, used uint64, percent float64) *Usage {
	if total == 0 || used > total || percent < 0 || percent > 100 || math.IsNaN(percent) || math.IsInf(percent, 0) {
		return nil
	}
	return &Usage{TotalBytes: total, UsedBytes: used, UsedPercent: percent}
}

func (c *Collector) Sample(ctx context.Context) error {
	c.sampleMu.Lock()
	defer c.sampleMu.Unlock()
	info, err := c.read.info(ctx)
	if err != nil || info == nil || info.Hostname == "" || info.OS == "" || info.Platform == "" || info.KernelVersion == "" {
		return errors.New("host sample unavailable")
	}
	logical, err := c.read.counts(ctx, true)
	if err != nil || logical < 1 {
		logical = runtime.NumCPU()
	}
	s := Status{APIVersion: "1", NodeID: c.nodeID, Hostname: info.Hostname,
		System:       System{OS: info.OS, Platform: info.Platform, Kernel: info.KernelVersion, Arch: runtime.GOARCH},
		AgentVersion: Version, MetricsScope: c.scope, AgentStartedAt: c.started,
		UptimeSeconds: info.Uptime, CPU: CPU{LogicalCount: logical},
	}
	var nextCPU *cpu.TimesStat
	times, err := c.read.times(ctx, false)
	if err == nil && len(times) > 0 {
		current := times[0]
		s.CPU.UsagePercent = cpuPercent(c.previous, &current)
		nextCPU = &current
	}
	if memory, err := c.read.memory(ctx); err == nil && memory != nil {
		s.Memory = usage(memory.Total, memory.Used, memory.UsedPercent)
	}
	if root, err := rootPath(); err == nil {
		if disk, err := c.read.disk(ctx, root); err == nil && disk != nil {
			s.Disk = usage(disk.Total, disk.Used, disk.UsedPercent)
		}
	}
	if ctx.Err() != nil {
		return errors.New("sample interrupted")
	}
	c.previous = nextCPU
	s.SampledAt = time.Now().UTC()
	c.mu.Lock()
	c.cached, c.ready = s, true
	c.mu.Unlock()
	return nil
}

func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		sampleCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		// Keep the previous timestamped sample on failure; never invent values.
		_ = c.Sample(sampleCtx)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Collector) Status() (Status, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.cached
	if s.CPU.UsagePercent != nil {
		v := *s.CPU.UsagePercent
		s.CPU.UsagePercent = &v
	}
	if s.Memory != nil {
		v := *s.Memory
		s.Memory = &v
	}
	if s.Disk != nil {
		v := *s.Disk
		s.Disk = &v
	}
	return s, c.ready
}
