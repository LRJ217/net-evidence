package history

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync/atomic"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/share"
)

const maxRecordBytes = 2 << 20
const historyPageSize = 40

var validID = regexp.MustCompile(`^\d{8}T\d{6}\.\d{9}-[0-9a-f]{16}$`)
var lastSavedAtUnixNano atomic.Int64

type Record struct {
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	SavedAt       time.Time         `json:"saved_at"`
	Result        diagnostic.Result `json:"result"`
}

type Summary struct {
	ID         string    `json:"id"`
	SavedAt    time.Time `json:"saved_at"`
	Target     string    `json:"target"`
	Outcome    string    `json:"outcome"`
	DurationMs int64     `json:"duration_ms"`
}

type Listing struct {
	Items        []Summary `json:"items"`
	InvalidFiles int       `json:"invalid_files"`
	TotalFiles   int       `json:"total_files"`
	TotalBytes   int64     `json:"total_bytes"`
	NextCursor   string    `json:"next_cursor,omitempty"`
}

type Store struct{ Dir string }

func DefaultDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(base, "NetEvidence", "history"), nil
}

func (s Store) Save(result diagnostic.Result) (Summary, error) {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return Summary{}, err
	}
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Summary{}, err
	}
	now := nextSaveTime()
	id := now.Format("20060102T150405.000000000") + "-" + hex.EncodeToString(random[:])
	record := Record{SchemaVersion: 1, ID: id, SavedAt: now, Result: result}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return Summary{}, err
	}
	data = append(data, '\n')
	if len(data) > maxRecordBytes {
		return Summary{}, fmt.Errorf("diagnostic result exceeds history limit")
	}
	temp, err := os.CreateTemp(s.Dir, ".record-*.tmp")
	if err != nil {
		return Summary{}, err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return Summary{}, err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return Summary{}, err
	}
	if err := temp.Close(); err != nil {
		return Summary{}, err
	}
	if err := os.Rename(temp.Name(), filepath.Join(s.Dir, id+".json")); err != nil {
		return Summary{}, err
	}
	return summarize(record), nil
}

// nextSaveTime keeps IDs ordered even when the system clock returns the same
// timestamp for consecutive saves (which can happen on Windows).
func nextSaveTime() time.Time {
	for {
		candidate := time.Now().UTC().UnixNano()
		previous := lastSavedAtUnixNano.Load()
		if candidate <= previous {
			candidate = previous + 1
		}
		if lastSavedAtUnixNano.CompareAndSwap(previous, candidate) {
			return time.Unix(0, candidate).UTC()
		}
	}
}

func (s Store) Load(id string) (Record, error) {
	if !validID.MatchString(id) {
		return Record{}, fmt.Errorf("invalid history ID")
	}
	file, err := os.Open(filepath.Join(s.Dir, id+".json"))
	if err != nil {
		return Record{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxRecordBytes+1))
	if err != nil {
		return Record{}, err
	}
	if len(data) > maxRecordBytes {
		return Record{}, fmt.Errorf("history record exceeds size limit")
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, fmt.Errorf("invalid history JSON: %w", err)
	}
	if record.SchemaVersion != 1 || record.ID != id || record.Result.SchemaVersion != 1 {
		return Record{}, fmt.Errorf("invalid history record version or ID")
	}
	return record, nil
}

func (s Store) Delete(id string) error {
	if !validID.MatchString(id) {
		return fmt.Errorf("invalid history ID")
	}
	return os.Remove(filepath.Join(s.Dir, id+".json"))
}

// PruneOlderThan removes valid diagnosis records older than the cutoff.
func (s Store) PruneOlderThan(cutoff time.Time) (int, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		if !validID.MatchString(id) {
			continue
		}
		record, err := s.Load(id)
		if err != nil || !record.SavedAt.Before(cutoff) {
			continue
		}
		if err := s.Delete(id); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (s Store) List() (Listing, error) {
	return s.ListPage("")
}

// ListPage reads records until one page of valid summaries is ready. The cursor is the ID of
// the last valid record returned, so newly saved records do not shift older
// pages while the user is browsing.
func (s Store) ListPage(afterID string) (Listing, error) {
	if afterID != "" && !validID.MatchString(afterID) {
		return Listing{}, fmt.Errorf("invalid history cursor")
	}
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return Listing{Items: []Summary{}}, nil
	}
	if err != nil {
		return Listing{}, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	listing := Listing{Items: []Summary{}}
	readableNames := make([]string, 0, len(names))
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(s.Dir, name))
		if err != nil {
			if afterID == "" {
				listing.InvalidFiles++
			}
			continue
		}
		listing.TotalFiles++
		listing.TotalBytes += info.Size()
		readableNames = append(readableNames, name)
	}
	for index, name := range readableNames {
		if afterID != "" && name >= afterID+".json" {
			continue
		}
		id := name[:len(name)-len(".json")]
		record, err := s.Load(id)
		if err != nil {
			listing.InvalidFiles++
			continue
		}
		listing.Items = append(listing.Items, summarize(record))
		if len(listing.Items) == historyPageSize {
			if index < len(readableNames)-1 {
				listing.NextCursor = id
			}
			break
		}
	}
	return listing, nil
}

func summarize(record Record) Summary {
	r := record.Result
	return Summary{
		ID: record.ID, SavedAt: record.SavedAt,
		Target:  share.Build(r).Evidence.Target.URL,
		Outcome: Outcome(r), DurationMs: r.DurationMs,
	}
}

// Outcome returns a fixed category without exposing raw diagnostic data.
func Outcome(r diagnostic.Result) string {
	outcome := "partial"
	switch {
	case isCanceled(r.DNS.Error) || isCanceled(r.TCP.Error) || isCanceled(r.TLS.Error) || isCanceled(r.HTTP.Error) ||
		(r.ProxyHTTP != nil && isCanceled(r.ProxyHTTP.Error)):
		outcome = "partial"
	case r.DNS.Status == diagnostic.StatusFailure || r.TCP.Status == diagnostic.StatusFailure ||
		r.TLS.Status == diagnostic.StatusFailure || r.HTTP.Status == diagnostic.StatusFailure:
		if r.ProxyHTTP != nil && r.ProxyHTTP.Status == diagnostic.StatusSuccess && r.ProxyHTTP.Data != nil && r.ProxyHTTP.Data.StatusCode < 400 {
			outcome = "proxy_accessible"
		} else {
			outcome = "failure"
		}
	case r.HTTP.Status == diagnostic.StatusSuccess && r.HTTP.Data != nil && r.HTTP.Data.StatusCode >= 400:
		outcome = "attention"
	case r.ProxyHTTP != nil && r.ProxyHTTP.Status == diagnostic.StatusFailure:
		outcome = "proxy_failure"
	case r.HTTP.Status == diagnostic.StatusSuccess:
		outcome = "success"
	}
	return outcome
}

func isCanceled(err *diagnostic.ProbeError) bool { return err != nil && err.Kind == "canceled" }
