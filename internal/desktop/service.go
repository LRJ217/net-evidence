package desktop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/history"
	"github.com/LRJ217/net-evidence/internal/share"
)

var ErrBusy = errors.New("a diagnosis is already running")

type Runner func(context.Context, string, diagnostic.Options) (diagnostic.Result, error)
type EventSink func(string, any)

type ProgressEvent struct {
	RunID string                  `json:"run_id"`
	Step  diagnostic.StepProgress `json:"step"`
}

type CompleteEvent struct {
	RunID        string              `json:"run_id"`
	Summary      *history.Summary    `json:"summary,omitempty"`
	Report       *share.Report       `json:"report,omitempty"`
	TCP          *diagnostic.TCPData `json:"tcp,omitempty"`
	Cancelled    bool                `json:"cancelled"`
	HistoryError string              `json:"history_error,omitempty"`
	Error        string              `json:"error,omitempty"`
}

type activeRun struct {
	id     string
	cancel context.CancelFunc
}

type Service struct {
	mu     sync.Mutex
	emitMu sync.Mutex
	active *activeRun
	store  history.Store
	run    Runner
	emit   EventSink
}

func New(store history.Store, emit EventSink, run Runner) *Service {
	if run == nil {
		run = diagnostic.Run
	}
	return &Service{store: store, emit: emit, run: run}
}

func (s *Service) Start(input string, timeoutSeconds int) (string, error) {
	if _, err := diagnostic.NormalizeTarget(input); err != nil {
		return "", err
	}
	if timeoutSeconds < 5 || timeoutSeconds > 60 {
		return "", fmt.Errorf("timeout must be between 5 and 60 seconds")
	}
	id, ctx, err := s.begin()
	if err != nil {
		return "", err
	}
	go s.execute(ctx, id, input, time.Duration(timeoutSeconds)*time.Second)
	return id, nil
}

func (s *Service) begin() (string, context.Context, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, err
	}
	id := hex.EncodeToString(random[:])
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if s.active != nil {
		s.mu.Unlock()
		cancel()
		return "", nil, ErrBusy
	}
	s.active = &activeRun{id: id, cancel: cancel}
	s.mu.Unlock()
	return id, ctx, nil
}

func (s *Service) execute(ctx context.Context, id, input string, timeout time.Duration) {
	result, err := s.run(ctx, input, diagnostic.Options{
		TotalTimeout:     timeout,
		HTTPTimeout:      timeout,
		ProbeSystemProxy: true,
		OnStep: func(step diagnostic.StepProgress) {
			s.send("diagnostic:progress", ProgressEvent{RunID: id, Step: step})
		},
	})
	event := CompleteEvent{RunID: id, Cancelled: errors.Is(ctx.Err(), context.Canceled)}
	if err != nil {
		event.Error = err.Error()
		s.finish(id)
		s.send("diagnostic:complete", event)
		return
	}
	report := share.Build(result)
	event.Report = &report
	event.TCP = result.TCP.Data
	summary, saveErr := s.store.Save(result)
	if saveErr != nil {
		event.HistoryError = saveErr.Error()
	} else {
		event.Summary = &summary
	}
	s.finish(id)
	s.send("diagnostic:complete", event)
}

func (s *Service) finish(id string) {
	s.mu.Lock()
	if s.active != nil && s.active.id == id {
		s.active = nil
	}
	s.mu.Unlock()
}

func (s *Service) send(name string, payload any) {
	if s.emit != nil {
		s.emitMu.Lock()
		defer s.emitMu.Unlock()
		s.emit(name, payload)
	}
}

func (s *Service) Cancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return false
	}
	s.active.cancel()
	return true
}

func (s *Service) Shutdown() { s.Cancel() }

func (s *Service) History() (history.Listing, error) { return s.store.List() }

func (s *Service) HistoryPage(afterID string) (history.Listing, error) {
	return s.store.ListPage(afterID)
}

func (s *Service) DeleteHistory(id string) error { return s.store.Delete(id) }

func (s *Service) PruneHistory(days int) (int, error) {
	if days != 30 && days != 90 && days != 180 {
		return 0, fmt.Errorf("unsupported retention period")
	}
	return s.store.PruneOlderThan(time.Now().AddDate(0, 0, -days))
}

func (s *Service) LocalTCP(id string) (*diagnostic.TCPData, error) {
	record, err := s.store.Load(id)
	if err != nil {
		return nil, err
	}
	return record.Result.TCP.Data, nil
}

func (s *Service) Report(id string) (share.Report, error) {
	record, err := s.store.Load(id)
	if err != nil {
		return share.Report{}, err
	}
	return share.Build(record.Result), nil
}

func (s *Service) Preview(id, format string) (string, error) {
	report, err := s.Report(id)
	if err != nil {
		return "", err
	}
	var data []byte
	switch format {
	case "json":
		data, err = share.RenderJSON(report)
	case "html":
		data, err = share.RenderHTML(report)
	case "issue":
		data = share.RenderIssue(report)
	default:
		return "", fmt.Errorf("unsupported report format")
	}
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Service) Compare(leftID, rightID string) (history.Comparison, error) {
	if leftID == rightID {
		return history.Comparison{}, fmt.Errorf("choose two different diagnoses")
	}
	left, err := s.store.Load(leftID)
	if err != nil {
		return history.Comparison{}, err
	}
	right, err := s.store.Load(rightID)
	if err != nil {
		return history.Comparison{}, err
	}
	return history.Compare(left, right), nil
}
