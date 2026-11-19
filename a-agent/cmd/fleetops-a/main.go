package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"fleetops/a-agent/internal/auth"
	"fleetops/a-agent/internal/collector"
	"fleetops/a-agent/internal/config"
	httpapi "fleetops/a-agent/internal/http"
)

var processStartedAt = time.Now().UTC()

const usage = "usage: fleetops-a init|serve|rotate-credential|issue-token|revoke-token|list-tokens --config X (issue-token requires --name Y; revoke-token requires --id Z)"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	command := args[0]
	switch command {
	case "init", "serve", "rotate-credential", "issue-token", "revoke-token", "list-tokens":
	default:
		return errors.New(usage)
	}
	flags := flag.NewFlagSet("fleetops-a", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // flag errors must not echo secret-looking arguments.
	path := flags.String("config", "", "configuration path")
	var name, id string
	if command == "issue-token" {
		flags.StringVar(&name, "name", "", "token name")
	}
	if command == "revoke-token" {
		flags.StringVar(&id, "id", "", "token ID")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New(usage)
	}
	p, err := config.Resolve(*path)
	if err != nil {
		return err
	}
	if command == "init" {
		if err := config.Ensure(p); err != nil {
			return err
		}
	}
	c, err := config.Load(p)
	if err != nil {
		return err
	}
	store := auth.Store{Dir: c.DataDir}
	var result any
	switch command {
	case "init":
		result, err = store.Init()
	case "rotate-credential":
		result, err = store.Rotate()
	case "issue-token":
		result, err = store.Issue(name)
	case "revoke-token":
		return store.Revoke(id)
	case "list-tokens":
		result, err = store.List()
	case "serve":
		return serve(ctx, c, store)
	}
	if err != nil {
		return err
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("cannot write command result")
	}
	return nil
}

func serve(ctx context.Context, c config.Config, store auth.Store) error {
	state, err := store.Read()
	if err != nil {
		return err
	}
	manager := auth.NewManager(store)
	source := collector.New(state.NodeID, c.MetricsScope, processStartedAt)
	server := httpapi.NewServer(c, manager, source)
	workerCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); manager.RunCleanup(workerCtx) }()
	go func() {
		defer workers.Done()
		source.Run(workerCtx, time.Duration(c.SampleIntervalSeconds)*time.Second)
	}()
	defer func() { cancel(); workers.Wait() }()
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServe() }()
	select {
	case err := <-finished:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.New("HTTP server could not start or stopped unexpectedly")
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-finished
			return errors.New("HTTP shutdown deadline exceeded")
		}
		<-finished
		return nil
	}
}
