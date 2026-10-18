package main

import (
	"os"
	"path/filepath"
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
