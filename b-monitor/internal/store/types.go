package store

import "time"

type Usage struct {
	TotalBytes  int64   `json:"totalBytes"`
	UsedBytes   int64   `json:"usedBytes"`
	UsedPercent float64 `json:"usedPercent"`
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
	UptimeSeconds  int64     `json:"uptimeSeconds"`
	CPU            CPU       `json:"cpu"`
	Memory         *Usage    `json:"memory"`
	Disk           *Usage    `json:"disk"`
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

type Observation struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	ExpectedNodeID string     `json:"expectedNodeId"`
	State          string     `json:"state"`
	Stale          bool       `json:"stale"`
	CheckedAt      *time.Time `json:"checkedAt"`
	SucceededAt    *time.Time `json:"succeededAt"`
	Failures       int        `json:"failures"`
	Message        string     `json:"message"`
	Status         *Status    `json:"status"`
}

type Event struct {
	ID         int64     `json:"id"`
	At         time.Time `json:"at"`
	TargetID   string    `json:"targetId"`
	TargetName string    `json:"targetName"`
	Kind       string    `json:"kind"`
	State      string    `json:"state"`
	Message    string    `json:"message"`
}

type Page struct {
	Events     []Event `json:"events"`
	NextBefore *int64  `json:"nextBefore"`
}

type Monitor struct {
	APIVersion        string        `json:"apiVersion"`
	MonitorID         string        `json:"monitorId"`
	InstanceID        string        `json:"instanceId"`
	StartedAt         time.Time     `json:"startedAt"`
	HeartbeatAt       *time.Time    `json:"heartbeatAt"`
	GeneratedAt       time.Time     `json:"generatedAt"`
	StaleAfterSeconds int           `json:"staleAfterSeconds"`
	StorageHealthy    bool          `json:"storageHealthy"`
	Targets           []Observation `json:"targets"`
}
