package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReportFileReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("old report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFile(path, "new report"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new report" {
		t.Fatalf("report was not replaced: %q %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary report was left behind: %+v %v", entries, err)
	}
}

func TestAnalyzeHARFileReturnsOnlySafeSummary(t *testing.T) {
	analysis, err := analyzeHARFile("docs/samples/browser-failure.har")
	if err != nil {
		t.Fatal(err)
	}
	if analysis.MainHost != "example.com" || analysis.NoResponse != 1 || analysis.HTTPErrors != 1 {
		t.Fatalf("unexpected HAR summary: %+v", analysis)
	}
	encoded, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "/v1/profile") || strings.Contains(string(encoded), "token=demo") {
		t.Fatalf("bridge summary contains raw HAR path or query: %s", encoded)
	}
	directory := t.TempDir()
	if _, err := analyzeHARFile(directory); err == nil || strings.Contains(err.Error(), directory) {
		t.Fatalf("directory was accepted or local path leaked: %v", err)
	}
}
