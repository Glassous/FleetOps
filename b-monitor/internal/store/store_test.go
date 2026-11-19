package store

import (
	"context"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPersistencePaginationAndRetention(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	o := Observation{ID: "one", Name: "One", State: "unreachable", Stale: true, CheckedAt: &now, Failures: 3}
	for i := 0; i < 7; i++ {
		e := Event{At: now.Add(time.Duration(i) * time.Second), TargetID: o.ID, TargetName: o.Name, Kind: "unreachable", State: o.State, Message: "offline"}
		if err := s.Save(ctx, o, &e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	loaded, err := s.Load(ctx)
	if err != nil || loaded[o.ID].Failures != 3 {
		t.Fatalf("load: %v", err)
	}
	page, err := s.Events(ctx, 3, nil)
	if err != nil || len(page.Events) != 3 || page.Events[0].ID != 7 || page.NextBefore == nil || *page.NextBefore != 5 {
		t.Fatalf("first page: %+v %v", page, err)
	}
	page, err = s.Events(ctx, 3, page.NextBefore)
	if err != nil || page.Events[0].ID != 4 || page.NextBefore == nil || *page.NextBefore != 2 {
		t.Fatalf("second page: %+v %v", page, err)
	}
	page, err = s.Events(ctx, 3, page.NextBefore)
	if err != nil || len(page.Events) != 1 || page.Events[0].ID != 1 || page.NextBefore != nil {
		t.Fatalf("last page: %+v %v", page, err)
	}
	if _, err = s.Events(ctx, 0, nil); err == nil {
		t.Fatal("invalid limit")
	}
	bad := int64(-1)
	if _, err = s.Events(ctx, 1, &bad); err == nil {
		t.Fatal("invalid cursor")
	}
	old := Event{At: now.Add(-31 * 24 * time.Hour), TargetID: "old", TargetName: "Old", Kind: "error", State: "auth_error"}
	if err := s.Save(ctx, Observation{ID: "old", State: "unknown"}, &old); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(ctx, now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	page, err = s.Events(ctx, 100, nil)
	if err != nil || len(page.Events) != 7 {
		t.Fatalf("retention: %+v %v", page, err)
	}
	if err := s.KeepTargets(ctx, []string{"one"}); err != nil {
		t.Fatal(err)
	}
	loaded, err = s.Load(ctx)
	if err != nil || len(loaded) != 1 {
		t.Fatal("deleted target observations retained")
	}
}

func TestConnectionPragmasSurviveReconnect(t *testing.T) {
	s := openTest(t)
	s.db.SetMaxIdleConns(0)
	for i := 0; i < 2; i++ {
		var timeout int
		if err := s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != 5000 {
			t.Fatalf("busy_timeout = %d: %v", timeout, err)
		}
		var journal string
		if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil || journal != "wal" {
			t.Fatalf("journal_mode = %s: %v", journal, err)
		}
	}
}

func TestTransactionFailureHealthAndHardBound(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	o := Observation{ID: "one", State: "unknown"}
	if err := s.Save(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	_, err := s.db.Exec(`CREATE TRIGGER reject_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'test failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	o.State = "unreachable"
	err = s.Save(ctx, o, &Event{At: time.Now(), TargetID: "one", Kind: "unreachable", State: o.State})
	if err == nil || s.Healthy() {
		t.Fatal("failed write appeared healthy")
	}
	loaded, err := s.Load(ctx)
	if err != nil || loaded["one"].State != "unknown" {
		t.Fatal("observation was committed without event")
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_event`); err != nil {
		t.Fatal(err)
	}
	if err = s.Save(ctx, o, nil); err != nil || s.Healthy() {
		t.Fatal("lost event health was hidden by later write")
	}
	_, err = s.db.Exec(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100005)
INSERT INTO events(at,target_id,target_name,kind,state,message) SELECT 0,'one','One','error','auth_error','test' FROM n`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Save(ctx, o, &Event{At: time.Now(), TargetID: "one", Kind: "error", State: "auth_error"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count); err != nil || count > maxEvents {
		t.Fatalf("unbounded events: %d %v", count, err)
	}
}
