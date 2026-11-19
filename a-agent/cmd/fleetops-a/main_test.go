package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fleetops/a-agent/internal/auth"
	"fleetops/a-agent/internal/config"
)

func TestCLIInitIssueListRevokeRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf", "agent.yaml")
	call := func(command string, extra ...string) ([]byte, error) {
		var out bytes.Buffer
		args := append([]string{command, "--config", path}, extra...)
		err := run(context.Background(), args, &out)
		return out.Bytes(), err
	}
	b, err := call("init")
	if err != nil {
		t.Fatal(err)
	}
	var identity auth.Identity
	if json.Unmarshal(b, &identity) != nil || identity.Credential == "" || identity.NodeID == "" {
		t.Fatal("invalid init output")
	}
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	if len(fields) != 2 {
		t.Fatal("init output has extra fields")
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
	b, err = call("init")
	if err == nil || len(b) != 0 {
		t.Fatal("repeat init exposed output or succeeded")
	}
	after, _ := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("repeat init changed state")
	}
	b, err = call("issue-token", "--name", "B巡检")
	if err != nil {
		t.Fatal(err)
	}
	var token auth.IssuedToken
	if json.Unmarshal(b, &token) != nil || token.Token == "" || token.ID == "" {
		t.Fatal("invalid issue output")
	}
	b, err = call("list-tokens")
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if json.Unmarshal(b, &list) != nil || len(list) != 1 || len(list[0]) != 2 || list[0]["name"] != "B巡检" || list[0]["id"] != token.ID {
		t.Fatal("list fields are not exactly id/name")
	}
	b, err = call("revoke-token", "--id", token.ID)
	if err != nil || len(b) != 0 {
		t.Fatal("revoke failed or produced output")
	}
	b, err = call("list-tokens")
	if err != nil || strings.TrimSpace(string(b)) != "[]" {
		t.Fatal("list should be empty")
	}
	b, err = call("rotate-credential")
	if err != nil {
		t.Fatal(err)
	}
	var rotated auth.Identity
	if json.Unmarshal(b, &rotated) != nil || rotated.NodeID != identity.NodeID || rotated.Credential == identity.Credential {
		t.Fatal("invalid rotation output")
	}
}

func TestServeShutdownAndBindFailure(t *testing.T) {
	store := auth.Store{Dir: filepath.Join(t.TempDir(), "data")}
	if _, err := store.Init(); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Listen: "127.0.0.1:0", DataDir: store.Dir, SampleIntervalSeconds: 5, MetricsScope: "host"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c, store) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown did not finish")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c.Listen = listener.Addr().String()
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := serve(ctx, c, store); err == nil {
		t.Fatal("bind failure was hidden")
	}
}

func TestCLIRejectsArgumentsWithoutSecretLeak(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown-secret"}, {"init"}, {"init", "--secret", "SECRET_VALUE"}, {"serve", "--config", "missing", "SECRET_VALUE"}} {
		var out bytes.Buffer
		err := run(context.Background(), args, &out)
		if err == nil || out.Len() != 0 || strings.Contains(err.Error(), "SECRET_VALUE") || strings.Contains(err.Error(), "unknown-secret") {
			t.Fatal("arguments not safely rejected")
		}
	}
}
