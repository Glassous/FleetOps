package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"fleetops/b-monitor/internal/auth"
	_ "modernc.org/sqlite"
)

const maxEvents = 100000

type Store struct {
	db               *sql.DB
	writeHealthy     atomic.Bool
	readHealthy      atomic.Bool
	retentionHealthy atomic.Bool
}

func Open(dir string) (*Store, error) {
	if err := auth.SecureDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "monitor.sqlite")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(absolute)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{}
	// Apply connection-local settings on every connection, including reconnects.
	query.Set("_pragma", "busy_timeout(5000)")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, `PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS observations (target_id TEXT PRIMARY KEY, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
 target_id TEXT NOT NULL, target_name TEXT NOT NULL, kind TEXT NOT NULL,
 state TEXT NOT NULL, message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_at ON events(at);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	s.writeHealthy.Store(true)
	s.readHealthy.Store(true)
	s.retentionHealthy.Store(true)
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Healthy() bool {
	return s.writeHealthy.Load() && s.readHealthy.Load() && s.retentionHealthy.Load()
}

func health(flag *atomic.Bool, err error, operation string) {
	flag.Store(err == nil)
	if err != nil {
		log.Printf("storage %s failed; storageHealthy=false", operation)
	}
}

func (s *Store) Save(ctx context.Context, o Observation, event *Event) (err error) {
	// A dropped observation/event transaction latches unhealthy until restart;
	// another target's successful write must not hide that durability failure.
	defer func() {
		if err != nil {
			health(&s.writeHealthy, err, "write")
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO observations(target_id, body) VALUES(?, ?)
ON CONFLICT(target_id) DO UPDATE SET body=excluded.body`, o.ID, string(body)); err != nil {
		return err
	}
	if event != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO events(at,target_id,target_name,kind,state,message) VALUES(?,?,?,?,?,?)`, event.At.UnixNano(), event.TargetID, event.TargetName, event.Kind, event.State, event.Message); err != nil {
			return err
		}
		// Retention also has a hard row bound, including during high event rates.
		if _, err = tx.ExecContext(ctx, `DELETE FROM events WHERE id <= (SELECT MAX(id)-? FROM events)`, maxEvents); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Load(ctx context.Context) (result map[string]Observation, err error) {
	defer func() { health(&s.readHealthy, err, "read") }()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT body FROM observations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result = make(map[string]Observation)
	for rows.Next() {
		var body string
		if err = rows.Scan(&body); err != nil {
			return nil, err
		}
		var o Observation
		if err = json.Unmarshal([]byte(body), &o); err != nil {
			return nil, err
		}
		result[o.ID] = o
	}
	return result, rows.Err()
}

// KeepTargets removes obsolete observations, not the retained event log.
func (s *Store) KeepTargets(ctx context.Context, ids []string) (err error) {
	defer func() { health(&s.writeHealthy, err, "target cleanup") }()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS active_targets (id TEXT PRIMARY KEY); DELETE FROM active_targets`); err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, `INSERT INTO active_targets(id) VALUES(?)`, id); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM observations WHERE target_id NOT IN (SELECT id FROM active_targets)`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Events(ctx context.Context, limit int, before *int64) (page Page, err error) {
	page.Events = []Event{}
	if limit < 1 || limit > 100 || (before != nil && *before < 1) {
		return page, errors.New("invalid pagination")
	}
	defer func() { health(&s.readHealthy, err, "events read") }()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT id,at,target_id,target_name,kind,state,message FROM events
WHERE (? IS NULL OR id < ?) ORDER BY id DESC LIMIT ?`, before, before, limit+1)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Event
		var at int64
		if err = rows.Scan(&e.ID, &at, &e.TargetID, &e.TargetName, &e.Kind, &e.State, &e.Message); err != nil {
			return page, err
		}
		e.At = time.Unix(0, at).UTC()
		page.Events = append(page.Events, e)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if len(page.Events) > limit {
		page.Events = page.Events[:limit]
		id := page.Events[limit-1].ID
		page.NextBefore = &id
	}
	return page, nil
}

func (s *Store) Prune(ctx context.Context, cutoff time.Time) (err error) {
	defer func() { health(&s.retentionHealthy, err, "retention") }()
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `DELETE FROM events WHERE at < ?`, cutoff.UnixNano())
	return err
}
