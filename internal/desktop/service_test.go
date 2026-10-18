package desktop

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/history"
)

func TestCancelAndPersistPartialDiagnosis(t *testing.T) {
	events := make(chan CompleteEvent, 2)
	started := make(chan struct{}, 1)
	runner := func(ctx context.Context, input string, options diagnostic.Options) (diagnostic.Result, error) {
		started <- struct{}{}
		<-ctx.Done()
		options.OnStep(diagnostic.StepProgress{ID: "dns", Status: diagnostic.StatusFailure})
		target, err := diagnostic.NormalizeTarget(input)
		if err != nil {
			return diagnostic.Result{}, err
		}
		return diagnostic.Result{SchemaVersion: 1, Target: target,
			DNS:         diagnostic.Step[diagnostic.DNSData]{ID: "dns", Status: diagnostic.StatusFailure, Error: &diagnostic.ProbeError{Kind: "canceled", Message: "private-token"}},
			TCP:         diagnostic.Step[diagnostic.TCPData]{ID: "tcp", Status: diagnostic.StatusSkipped},
			TLS:         diagnostic.Step[diagnostic.TLSData]{ID: "tls", Status: diagnostic.StatusSkipped},
			HTTP:        diagnostic.Step[diagnostic.HTTPData]{ID: "http", Status: diagnostic.StatusSkipped},
			Environment: diagnostic.Step[diagnostic.EnvironmentData]{ID: "environment", Status: diagnostic.StatusSuccess},
		}, nil
	}
	service := New(history.Store{Dir: t.TempDir()}, func(name string, payload any) {
		if name == "diagnostic:complete" {
			events <- payload.(CompleteEvent)
		}
	}, runner)
	id, err := service.Start("http://127.0.0.1:8080/private?token=private-token", 20)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := service.Start("example.com", 20); !errors.Is(err, ErrBusy) {
		t.Fatalf("wanted busy error, got %v", err)
	}
	if !service.Cancel() {
		t.Fatal("cancel did not find active diagnosis")
	}
	select {
	case complete := <-events:
		if complete.RunID != id || !complete.Cancelled || complete.Summary == nil || complete.Report == nil {
			t.Fatalf("incomplete cancel event: %+v", complete)
		}
		if strings.Contains(complete.Report.Evidence.Target.URL, "private-token") {
			t.Fatal("completion leaked target token")
		}
		if _, err := service.Preview(complete.Summary.ID, "raw-json"); err == nil {
			t.Fatal("desktop preview accepted raw format")
		}
		preview, err := service.Preview(complete.Summary.ID, "issue")
		if err != nil || strings.Contains(preview, "private-token") {
			t.Fatalf("unsafe preview: %v %s", err, preview)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("completion event was not delivered")
	}
	if service.Cancel() {
		t.Fatal("finished diagnosis remained active")
	}
}
