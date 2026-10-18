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
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/share"
)

const maxRecordBytes = 2 << 20

var validID = regexp.MustCompile(`^\d{8}T\d{6}\.\d{9}-[0-9a-f]{16}$`)

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
	now := time.Now().UTC()
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

func (s Store) List() (Listing, error) {
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
	for _, name := range names {
		if len(listing.Items) >= 100 {
			break
		}
		id := name[:len(name)-len(".json")]
		record, err := s.Load(id)
		if err != nil {
			listing.InvalidFiles++
			continue
		}
		listing.Items = append(listing.Items, summarize(record))
	}
	return listing, nil
}

func summarize(record Record) Summary {
	r := record.Result
	outcome := "partial"
	switch {
	case r.DNS.Status == diagnostic.StatusFailure || r.TCP.Status == diagnostic.StatusFailure ||
		r.TLS.Status == diagnostic.StatusFailure || r.HTTP.Status == diagnostic.StatusFailure:
		outcome = "failure"
	case r.HTTP.Status == diagnostic.StatusSuccess && r.HTTP.Data != nil && r.HTTP.Data.StatusCode >= 400:
		outcome = "attention"
	case r.HTTP.Status == diagnostic.StatusSuccess:
		outcome = "success"
	}
	return Summary{
		ID: record.ID, SavedAt: record.SavedAt,
		Target:  share.Build(r).Evidence.Target.URL,
		Outcome: outcome, DurationMs: r.DurationMs,
	}
}
