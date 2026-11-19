package poller

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"fleetops/b-monitor/internal/store"
)

func object(raw []byte, required []string, nullable map[string]bool) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errors.New("expected object")
	}
	// Reject aliases that Go's case-insensitive struct decoding would use to override canonical keys.
	for key := range fields {
		for _, canonical := range required {
			if key != canonical && strings.EqualFold(key, canonical) {
				return nil, errors.New("non-canonical required field name")
			}
		}
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || (bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !nullable[key]) {
			return nil, errors.New("required field missing or null")
		}
	}
	return fields, nil
}

// Go zero values cannot distinguish missing metrics from valid zeros or nulls.
func decodeStatus(body []byte) (*store.Status, error) {
	fields, err := object(body, []string{"apiVersion", "nodeId", "hostname", "system", "agentVersion", "metricsScope", "sampledAt", "agentStartedAt", "uptimeSeconds", "cpu", "memory", "disk"}, map[string]bool{"memory": true, "disk": true})
	if err != nil {
		return nil, err
	}
	if _, err = object(fields["system"], []string{"os", "platform", "kernel", "arch"}, nil); err != nil {
		return nil, err
	}
	if _, err = object(fields["cpu"], []string{"logicalCount", "usagePercent"}, map[string]bool{"usagePercent": true}); err != nil {
		return nil, err
	}
	for _, key := range []string{"memory", "disk"} {
		if !bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
			if _, err = object(fields[key], []string{"totalBytes", "usedBytes", "usedPercent"}, nil); err != nil {
				return nil, err
			}
		}
	}
	var s store.Status
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	if s.APIVersion != "1" || s.NodeID == "" || (s.MetricsScope != "host" && s.MetricsScope != "container-test") || s.SampledAt.IsZero() || s.AgentStartedAt.IsZero() || s.UptimeSeconds < 0 || s.CPU.LogicalCount < 1 {
		return nil, errors.New("invalid status values")
	}
	if s.CPU.UsagePercent != nil && (*s.CPU.UsagePercent < 0 || *s.CPU.UsagePercent > 100) {
		return nil, errors.New("invalid CPU percentage")
	}
	for _, u := range []*store.Usage{s.Memory, s.Disk} {
		if u != nil && (u.TotalBytes < 0 || u.UsedBytes < 0 || u.UsedPercent < 0 || u.UsedPercent > 100) {
			return nil, errors.New("invalid usage")
		}
	}
	return &s, nil
}
