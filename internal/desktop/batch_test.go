package desktop

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/history"
)

func batchResult(input string, failed bool) diagnostic.Result {
	target, _ := diagnostic.NormalizeTarget(input)
	r := diagnostic.Result{SchemaVersion: 1, ToolVersion: diagnostic.ToolVersion, StartedAt: time.Now().UTC(),
		Target: target,
		DNS: diagnostic.Step[diagnostic.DNSData]{ID: "dns", Status: diagnostic.StatusSuccess,
			Data: &diagnostic.DNSData{IPv4: []string{"192.168.1.20"}}},
		TCP: diagnostic.Step[diagnostic.TCPData]{ID: "tcp", Status: diagnostic.StatusSuccess},
		TLS: diagnostic.Step[diagnostic.TLSData]{ID: "tls", Status: diagnostic.StatusSuccess},
		HTTP: diagnostic.Step[diagnostic.HTTPData]{ID: "http", Status: diagnostic.StatusSuccess,
			Data: &diagnostic.HTTPData{StatusCode: 200, FinalURL: "https://example.com/private?token=secret-token"}},
		Environment: diagnostic.Step[diagnostic.EnvironmentData]{ID: "environment", Status: diagnostic.StatusSuccess},
	}
	if failed {
		r.TCP.Status = diagnostic.StatusFailure
		r.TCP.Error = &diagnostic.ProbeError{Kind: "timeout", Message: "secret-token"}
		r.TLS.Status = diagnostic.StatusSkipped
		r.HTTP.Status = diagnostic.StatusSkipped
		r.HTTP.Data = nil
	}
	return r
}

func TestObservationStoresFailuresAndFirstSuccessOnly(t *testing.T) {
	store := history.Store{Dir: t.TempDir()}
	var samples []ObservationSample
	var complete ObservationComplete
	calls := 0
	s := New(store, func(name string, payload any) {
		switch name {
		case "observation:sample":
			samples = append(samples, payload.(ObservationSample))
		case "observation:complete":
			complete = payload.(ObservationComplete)
		}
	}, func(_ context.Context, input string, _ diagnostic.Options) (diagnostic.Result, error) {
		calls++
		return batchResult(input, calls == 2), nil
	})
	s.observe(context.Background(), "run-1", "https://example.com/private?token=secret-token", time.Second, time.Millisecond, 3)
	if complete.Samples != 3 || complete.Successes != 2 || complete.Failures != 1 || len(samples) != 3 {
		t.Fatalf("wrong observation summary: %+v %+v", complete, samples)
	}
	if samples[0].Saved == nil || samples[1].Saved == nil || samples[2].Saved != nil || samples[1].FailureLayer != "tcp" {
		t.Fatalf("wrong sample retention or failure layer: %+v", samples)
	}
	listing, err := store.List()
	if err != nil || listing.TotalFiles != 2 {
		t.Fatalf("wrong retained history: %+v %v", listing, err)
	}
	encoded, _ := json.Marshal(samples)
	if strings.Contains(string(encoded), "secret-token") || strings.Contains(string(encoded), "192.168.1.20") {
		t.Fatalf("observation event leaked raw evidence: %s", encoded)
	}
}

func TestObservationCancelStopsAndDoesNotSavePartialSample(t *testing.T) {
	started := make(chan struct{}, 1)
	completed := make(chan ObservationComplete, 1)
	store := history.Store{Dir: t.TempDir()}
	s := New(store, func(name string, payload any) {
		if name == "observation:complete" {
			completed <- payload.(ObservationComplete)
		}
	}, func(ctx context.Context, input string, _ diagnostic.Options) (diagnostic.Result, error) {
		started <- struct{}{}
		<-ctx.Done()
		r := batchResult(input, true)
		r.TCP.Error.Kind = "canceled"
		return r, nil
	})
	if _, err := s.StartObservation("example.com", 10, 10, 5); err != nil {
		t.Fatal(err)
	}
	<-started
	if !s.Cancel() {
		t.Fatal("active observation was not cancelled")
	}
	select {
	case event := <-completed:
		if !event.Cancelled {
			t.Fatalf("cancel was not reported: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observation did not stop")
	}
	listing, err := store.List()
	if err != nil || listing.TotalFiles != 0 {
		t.Fatalf("cancelled sample was saved: %+v %v", listing, err)
	}
}

func TestVariantURLsDiscardPathAndRejectNonRootTargets(t *testing.T) {
	urls, err := variantURLs("https://www.example.co.uk/private?token=secret-token")
	if err != nil || len(urls) != 4 || urls[0] != "http://example.co.uk/" || urls[3] != "https://www.example.co.uk/" {
		t.Fatalf("wrong variant URLs: %v %v", urls, err)
	}
	for _, url := range urls {
		if strings.Contains(url, "private") || strings.Contains(url, "secret-token") {
			t.Fatalf("variant retained sensitive path: %s", url)
		}
	}
	for _, input := range []string{"https://sub.example.com", "https://example.com:8443", "http://127.0.0.1"} {
		if _, err := variantURLs(input); err == nil {
			t.Fatalf("accepted unsupported variant target %q", input)
		}
	}
}

func TestVariantResultsDoNotLeakOriginalURLOrRedirectPath(t *testing.T) {
	results := make(chan VariantResult, 4)
	complete := make(chan VariantsComplete, 1)
	s := New(history.Store{Dir: t.TempDir()}, func(name string, payload any) {
		switch name {
		case "variants:result":
			results <- payload.(VariantResult)
		case "variants:complete":
			complete <- payload.(VariantsComplete)
		}
	}, func(_ context.Context, input string, _ diagnostic.Options) (diagnostic.Result, error) {
		return batchResult(input, false), nil
	})
	id, err := s.StartVariants("https://example.com/private?token=secret-token", 10)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-complete:
		if event.RunID != id || event.Cancelled {
			t.Fatalf("wrong variant completion: %+v", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("variant comparison did not finish")
	}
	if len(results) != 4 {
		t.Fatalf("got %d variant results", len(results))
	}
	for i := 0; i < 4; i++ {
		row := <-results
		encoded, _ := json.Marshal(row)
		if strings.Contains(string(encoded), "secret-token") || strings.Contains(string(encoded), "192.168.1.20") || row.Outcome != "success" || row.HTTPCode != 200 {
			t.Fatalf("unsafe or incomplete variant result: %s", encoded)
		}
	}
}
