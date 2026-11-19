package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fleetops/b-monitor/internal/auth"
	"fleetops/b-monitor/internal/config"
)

func TestCLIInitRotateAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	var output bytes.Buffer
	if err := run([]string{"init", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	var first auth.Credential
	if err := json.Unmarshal(output.Bytes(), &first); err != nil || first.NodeID == "" || first.Credential == "" {
		t.Fatal("expected one credential JSON")
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	targets, err := config.LoadTargets(c.TargetsFile)
	if err != nil || len(targets) != 0 {
		t.Fatal("init must allow empty targets")
	}
	before, err := os.ReadFile(filepath.Join(c.DataDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"init", "--config", path}, &output); err == nil || output.Len() != 0 {
		t.Fatal("repeat init emitted secret or succeeded")
	}
	after, _ := os.ReadFile(filepath.Join(c.DataDir, "identity.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("repeat init overwrote identity")
	}
	if err := run([]string{"rotate-credential", "--config", path}, &output); err != nil {
		t.Fatal(err)
	}
	var next auth.Credential
	if err := json.Unmarshal(output.Bytes(), &next); err != nil || next.NodeID != first.NodeID || next.Credential == first.Credential {
		t.Fatal("rotation invalid")
	}
	a, err := auth.New(c.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Login(first.Credential, "local"); err == nil {
		t.Fatal("old credential still accepted")
	}
	if _, err = a.Login(next.Credential, "local"); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"bad"}, {"init", "--wat"}, {"init", "unexpected"}, {"serve", "--config", ""}} {
		if err := run(args, &output); err == nil {
			t.Fatal("invalid CLI accepted")
		}
	}
}
