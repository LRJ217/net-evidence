package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

func sampleResult(target string, tcp diagnostic.Status, tcpMs int64) diagnostic.Result {
	return diagnostic.Result{
		SchemaVersion: 1, ToolVersion: diagnostic.ToolVersion, StartedAt: time.Now().UTC(),
		Target:      diagnostic.Target{Input: target, URL: target, Scheme: "http", Host: "127.0.0.1", Port: "8080", Address: "127.0.0.1:8080"},
		DNS:         diagnostic.Step[diagnostic.DNSData]{ID: "dns", Status: diagnostic.StatusSuccess, DurationMs: 2},
		TCP:         diagnostic.Step[diagnostic.TCPData]{ID: "tcp", Status: tcp, DurationMs: tcpMs},
		TLS:         diagnostic.Step[diagnostic.TLSData]{ID: "tls", Status: diagnostic.StatusSkipped},
		HTTP:        diagnostic.Step[diagnostic.HTTPData]{ID: "http", Status: diagnostic.StatusSkipped},
		Environment: diagnostic.Step[diagnostic.EnvironmentData]{ID: "environment", Status: diagnostic.StatusSuccess},
	}
}

func TestSaveListLoadAndCompare(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	secret := "private-token-123"
	left, err := store.Save(sampleResult("http://127.0.0.1:8080/private?token="+secret, diagnostic.StatusFailure, 14))
	if err != nil {
		t.Fatal(err)
	}
	right, err := store.Save(sampleResult("http://127.0.0.1:8080/private?token="+secret, diagnostic.StatusSuccess, 9))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(left.Target, secret) || !strings.Contains(left.Target, "[QUERY_REDACTED]") {
		t.Fatalf("history summary leaked target: %q", left.Target)
	}
	listing, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Items) != 2 || listing.Items[0].ID != right.ID || listing.Items[1].ID != left.ID {
		t.Fatalf("wrong history order: %+v", listing)
	}
	if listing.TotalFiles != 2 || listing.TotalBytes <= 0 {
		t.Fatalf("history usage was not counted: %+v", listing)
	}
	leftRecord, err := store.Load(left.ID)
	if err != nil {
		t.Fatal(err)
	}
	rightRecord, err := store.Load(right.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(leftRecord.Result.Target.URL, secret) {
		t.Fatal("raw local evidence was lost")
	}
	comparison := Compare(leftRecord, rightRecord)
	if comparison.Rows[1].ID != "tcp" || !comparison.Rows[1].Changed || comparison.Rows[1].DeltaMs != -5 {
		t.Fatalf("wrong TCP comparison: %+v", comparison.Rows[1])
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	listing, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	if listing.InvalidFiles != 1 || len(listing.Items) != 2 {
		t.Fatalf("invalid history was not isolated: %+v", listing)
	}
	if _, err := store.Load("../other"); err == nil {
		t.Fatal("accepted path traversal ID")
	}
}

func TestRapidSavesKeepHistoryOrder(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	previous := ""
	for i := 0; i < 32; i++ {
		summary, err := store.Save(sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1))
		if err != nil {
			t.Fatal(err)
		}
		if summary.ID <= previous {
			t.Fatalf("history ID did not increase: %q after %q", summary.ID, previous)
		}
		previous = summary.ID
	}
}

func TestHistoryPagesKeepOlderRecordsReachable(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	for i := 0; i < 85; i++ {
		if _, err := store.Save(sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := store.List()
	if err != nil || len(first.Items) != historyPageSize || first.NextCursor == "" || first.InvalidFiles != 1 || first.TotalFiles != 86 {
		t.Fatalf("first page: %+v %v", first, err)
	}
	if _, err := store.Save(sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1)); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, item := range first.Items {
		seen[item.ID] = true
	}
	cursor := first.NextCursor
	for cursor != "" {
		page, err := store.ListPage(cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatalf("duplicate paginated record: %s", item.ID)
			}
			seen[item.ID] = true
		}
		cursor = page.NextCursor
	}
	if len(seen) != 85 {
		t.Fatalf("older records missing: got %d, want 85", len(seen))
	}
	if _, err := store.ListPage("../bad"); err == nil {
		t.Fatal("accepted invalid history cursor")
	}
}

func TestDeleteAndPruneHistory(t *testing.T) {
	store := Store{Dir: t.TempDir()}
	old, err := store.Save(sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1))
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.Save(sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1))
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(store.Dir, old.ID+".json")
	data, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record.SavedAt = time.Now().AddDate(0, 0, -100)
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	removed, err := store.PruneOlderThan(time.Now().AddDate(0, 0, -90))
	if err != nil || removed != 1 {
		t.Fatalf("wrong prune result: %d %v", removed, err)
	}
	if _, err := store.Load(old.ID); !os.IsNotExist(err) {
		t.Fatalf("old record survived pruning: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "broken.json")); err != nil {
		t.Fatalf("invalid file was removed: %v", err)
	}
	if err := store.Delete("../other"); err == nil {
		t.Fatal("delete accepted a traversal ID")
	}
	if err := store.Delete(current.ID); err != nil {
		t.Fatal(err)
	}
	listing, err := store.List()
	if err != nil || listing.TotalFiles != 1 || listing.InvalidFiles != 1 {
		t.Fatalf("wrong remaining history: %+v %v", listing, err)
	}
}

func TestProxyAccessibleSummaryAndComparison(t *testing.T) {
	directFailure := sampleResult("https://example.com/", diagnostic.StatusFailure, 3000)
	directFailure.Target = diagnostic.Target{URL: "https://example.com/", Scheme: "https", Host: "example.com", Port: "443"}
	directFailure.ProxyHTTP = &diagnostic.Step[diagnostic.HTTPData]{ID: "proxy_http", Status: diagnostic.StatusSuccess, DurationMs: 120,
		Data: &diagnostic.HTTPData{StatusCode: 200, Transport: "system_proxy"}}
	store := Store{Dir: t.TempDir()}
	left, err := store.Save(sampleResult("https://example.com/", diagnostic.StatusFailure, 3000))
	if err != nil {
		t.Fatal(err)
	}
	right, err := store.Save(directFailure)
	if err != nil {
		t.Fatal(err)
	}
	if right.Outcome != "proxy_accessible" {
		t.Fatalf("wrong outcome: %+v", right)
	}
	leftRecord, _ := store.Load(left.ID)
	rightRecord, _ := store.Load(right.ID)
	comparison := Compare(leftRecord, rightRecord)
	last := comparison.Rows[len(comparison.Rows)-1]
	if last.ID != "proxy_http" || !last.Changed || last.RightStatus != diagnostic.StatusSuccess {
		t.Fatalf("proxy comparison missing: %+v", last)
	}
}

func TestCanceledSummaryIsPartial(t *testing.T) {
	r := sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1)
	r.HTTP = diagnostic.Step[diagnostic.HTTPData]{ID: "http", Status: diagnostic.StatusFailure,
		Error: &diagnostic.ProbeError{Kind: "canceled"}}
	summary, err := (Store{Dir: t.TempDir()}).Save(r)
	if err != nil || summary.Outcome != "partial" {
		t.Fatalf("canceled outcome: %+v %v", summary, err)
	}
}

func TestProxyFailureIsVisibleEvenWhenDirectWorks(t *testing.T) {
	r := sampleResult("http://127.0.0.1:8080/", diagnostic.StatusSuccess, 1)
	r.HTTP = diagnostic.Step[diagnostic.HTTPData]{ID: "http", Status: diagnostic.StatusSuccess,
		Data: &diagnostic.HTTPData{StatusCode: 200}}
	r.ProxyHTTP = &diagnostic.Step[diagnostic.HTTPData]{ID: "proxy_http", Status: diagnostic.StatusFailure,
		Error: &diagnostic.ProbeError{Kind: "connection_refused"}}
	summary, err := (Store{Dir: t.TempDir()}).Save(r)
	if err != nil || summary.Outcome != "proxy_failure" {
		t.Fatalf("proxy outcome: %+v %v", summary, err)
	}
}
