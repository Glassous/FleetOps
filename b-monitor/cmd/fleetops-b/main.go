package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fleetops/b-monitor/internal/auth"
	"fleetops/b-monitor/internal/config"
	httpapi "fleetops/b-monitor/internal/http"
	"fleetops/b-monitor/internal/poller"
	"fleetops/b-monitor/internal/store"
	"gopkg.in/yaml.v3"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: fleetops-b init|serve|rotate-credential --config PATH")
	}
	command := args[0]
	if command != "init" && command != "serve" && command != "rotate-credential" {
		return errors.New("unknown command; use init, serve or rotate-credential")
	}
	flags := flag.NewFlagSet("fleetops-b "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "config.yaml", "configuration YAML path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *path == "" {
		return errors.New("usage: fleetops-b init|serve|rotate-credential --config PATH")
	}
	abs, err := filepath.Abs(*path)
	if err != nil {
		return err
	}
	if command == "init" {
		return initialize(abs, output)
	}
	c, err := config.Load(abs)
	if err != nil {
		return err
	}
	if command == "rotate-credential" {
		credential, err := auth.ChangeCredential(c.DataDir, true)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(credential)
	}
	return serve(c)
}

func initialize(path string, output io.Writer) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	unlock, err := auth.AcquireLock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		data, err := yaml.Marshal(config.Defaults())
		if err != nil {
			return err
		}
		if err := auth.AtomicWrite(path, data, false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(c.TargetsFile); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(c.TargetsFile), 0700); err != nil {
			return err
		}
		if err := auth.AtomicWrite(c.TargetsFile, []byte("targets: []\n"), false); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err := config.LoadTargets(c.TargetsFile); err != nil {
		return err
	}
	credential, err := auth.ChangeCredential(c.DataDir, false)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(credential)
}

func serve(c config.Config) error {
	targets, err := config.LoadTargets(c.TargetsFile)
	if err != nil {
		return err
	}
	state, err := auth.ReadState(c.DataDir)
	if err != nil {
		return err
	}
	if err := auth.SecureDir(c.DataDir); err != nil {
		return err
	}
	unlock, err := auth.AcquireLock(filepath.Join(c.DataDir, "serve.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	s, err := store.Open(c.DataDir)
	if err != nil {
		return errors.New("cannot open monitor storage")
	}
	defer s.Close()
	a, err := auth.New(c.DataDir)
	if err != nil {
		return err
	}
	p, err := poller.New(c, targets, s, state.NodeID)
	if err != nil {
		return errors.New("cannot load monitor observations")
	}
	srv := httpapi.New(c, a, p, s)
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return fmt.Errorf("cannot listen: %w", err)
	}
	defer listener.Close()
	log.Print("WARNING: B serves plaintext HTTP; use trusted networking or an HTTPS reverse proxy; credentials and sessions require transport protection")
	for i, t := range targets {
		if strings.HasPrefix(t.URL, "http://") {
			log.Printf("WARNING: target #%d uses plaintext HTTP; its machine token is not transport-encrypted", i+1)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pollDone := make(chan struct{})
	go func() { defer close(pollDone); p.Run(ctx) }()
	httpDone := make(chan error, 1)
	go func() { httpDone <- srv.Serve(listener) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-httpDone:
	}
	stop() // Cancel in-flight polls before draining HTTP and closing SQLite.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
	}
	<-pollDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("HTTP server stopped unexpectedly")
	}
	return nil
}
