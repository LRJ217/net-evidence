package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	report, err := a.service.Report(id)
	if err != nil {
		return "", err
	}
	var suffix, pattern string
	switch format {
	case "json":
		suffix, pattern = "json", "*.json"
	case "html":
		suffix, pattern = "html", "*.html"
	case "issue":
		suffix, pattern = "md", "*.md"
	}
	filename := defaultReportName(report, suffix)
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
	if err := writeReportFile(path, content); err != nil {
		return "", err
	}
	return path, nil
}

func defaultReportName(report share.Report, suffix string) string {
	host := report.Evidence.Target.Host
	if strings.HasPrefix(host, "[") || host == "" {
		host = "target"
	}
	host = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, host)
	return fmt.Sprintf("net-evidence-%s-%s.%s", host, report.Evidence.StartedAt.Local().Format("20060102-150405"), suffix)
}

// The native save dialog asks the user before replacing an existing file.
// Write to a sibling temporary file so a failed write leaves the old report intact.
func writeReportFile(path, content string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".net-evidence-report-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.WriteString(content); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}
