package history

import (
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
