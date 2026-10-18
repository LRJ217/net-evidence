package main

import (
	"context"
	"os"
	"sync"

	"github.com/LRJ217/net-evidence/internal/desktop"
	"github.com/LRJ217/net-evidence/internal/diagnostic"
	"github.com/LRJ217/net-evidence/internal/history"
	"github.com/LRJ217/net-evidence/internal/share"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	mu      sync.RWMutex
	ctx     context.Context
	service *desktop.Service
}

func NewApp(historyDir string) *App {
	app := &App{}
	app.service = desktop.New(history.Store{Dir: historyDir}, app.emit, nil)
	return app
}

func (a *App) startup(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
}

func (a *App) shutdown(context.Context) { a.service.Shutdown() }

func (a *App) emit(name string, payload any) {
	a.mu.RLock()
	ctx := a.ctx
	a.mu.RUnlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, payload)
	}
}

func (a *App) StartDiagnosis(input string, timeoutSeconds int) (string, error) {
	return a.service.Start(input, timeoutSeconds)
}

func (a *App) CancelDiagnosis() bool { return a.service.Cancel() }

func (a *App) ListHistory() (history.Listing, error) { return a.service.History() }

func (a *App) DeleteHistory(id string) error { return a.service.DeleteHistory(id) }

func (a *App) PruneHistory(days int) (int, error) { return a.service.PruneHistory(days) }

func (a *App) LocalTCP(id string) (*diagnostic.TCPData, error) { return a.service.LocalTCP(id) }

func (a *App) LoadReport(id string) (share.Report, error) { return a.service.Report(id) }

func (a *App) PreviewReport(id, format string) (string, error) {
	return a.service.Preview(id, format)
}

func (a *App) CompareHistory(leftID, rightID string) (history.Comparison, error) {
	return a.service.Compare(leftID, rightID)
}

func (a *App) ExportReport(id, format string) (string, error) {
	content, err := a.service.Preview(id, format)
	if err != nil {
		return "", err
	}
	var filename, pattern string
	switch format {
	case "json":
		filename, pattern = "net-evidence-report.json", "*.json"
	case "html":
		filename, pattern = "net-evidence-report.html", "*.html"
	case "issue":
		filename, pattern = "net-evidence-issue.md", "*.md"
	}
	a.mu.RLock()
	ctx := a.ctx
	a.mu.RUnlock()
	path, err := runtime.SaveFileDialog(ctx, runtime.SaveDialogOptions{
		Title: "保存脱敏报告", DefaultFilename: filename,
		Filters: []runtime.FileFilter{{DisplayName: "报告文件", Pattern: pattern}},
	})
	if err != nil || path == "" {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := file.WriteString(content)
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return path, nil
}
