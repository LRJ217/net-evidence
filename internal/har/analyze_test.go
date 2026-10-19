package har

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAnalyzeBrowserFailuresWithoutLeakingHARSecrets(t *testing.T) {
	input := `{"log":{"version":"1.2","entries":[
		{"startedDateTime":"2026-10-19T09:00:00+08:00","time":120,"request":{"method":"GET","url":"https://site.example/","headers":[{"name":"Cookie","value":"SECRET_COOKIE"}]},"response":{"status":200,"content":{"mimeType":"text/html","text":"SECRET_BODY"}}},
		{"startedDateTime":"2026-10-19T09:00:01+08:00","time":450,"_resourceType":"script","request":{"method":"GET","url":"https://user:password@cdn.example/private-script.js?token=SECRET_TOKEN"},"response":{"status":503,"content":{}},"timings":{"dns":20,"connect":40,"ssl":80,"wait":300,"receive":10}},
		{"startedDateTime":"2026-10-19T09:00:02+08:00","time":90,"request":{"method":"GET","url":"https://192.168.1.20/private-image.png"},"response":{"status":0,"content":{"mimeType":"image/png"}},"_error":"SECRET_ERROR"},
		{"startedDateTime":"2026-10-19T09:00:03+08:00","time":3800,"request":{"method":"POST","url":"https://site.example/api/private?key=SECRET_KEY","postData":{"text":"SECRET_POST"}},"response":{"status":200,"content":{"mimeType":"application/json"}},"timings":{"wait":3600}},
		{"request":{"url":"data:text/plain,SECRET_DATA"},"response":{"status":200}}
	]}}`
	result, err := Analyze(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalEntries != 5 || result.SupportedEntries != 4 || result.IgnoredEntries != 1 ||
		result.NoResponse != 1 || result.HTTPErrors != 1 || result.Slow != 1 || !result.DocumentOK ||
		result.MainHost != "site.example" || result.OtherHostRequests != 2 {
		t.Fatalf("unexpected summary: %+v", result)
	}
	if len(result.Rows) != 3 || result.Rows[0].Issue != "no_response" ||
		result.Rows[1].Issue != "server_error" || result.Rows[2].Issue != "slow" ||
		result.Rows[0].Host != "[IP_REDACTED]" || result.Rows[1].Kind != "script" {
		t.Fatalf("unexpected rows: %+v", result.Rows)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET_COOKIE", "SECRET_BODY", "SECRET_TOKEN", "SECRET_KEY", "SECRET_POST", "SECRET_ERROR", "SECRET_DATA", "password", "192.168.1.20", "private-script.js", "private-image.png"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("analysis leaked %q: %s", secret, encoded)
		}
	}
	if !strings.Contains(string(encoded), "[PATH_REDACTED]") {
		t.Fatalf("redacted path marker missing: %s", encoded)
	}
}

func TestAnalyzeRejectsInvalidHARWithoutEchoingInput(t *testing.T) {
	for _, value := range []string{`{"log":{"entries":null}}`, `SECRET_INVALID_JSON`, `{"entries":[]}`} {
		_, err := Analyze(strings.NewReader(value))
		if err == nil || strings.Contains(err.Error(), "SECRET_") {
			t.Fatalf("invalid HAR returned unsafe error: %v", err)
		}
	}
}

func TestSyntheticDemoFixture(t *testing.T) {
	file, err := os.Open("../../docs/samples/browser-failure.har")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result, err := Analyze(file)
	if err != nil {
		t.Fatal(err)
	}
	if result.SupportedEntries != 4 || result.NoResponse != 1 || result.HTTPErrors != 1 ||
		result.Slow != 1 || !result.DocumentOK || len(result.Rows) != 3 {
		t.Fatalf("demo fixture no longer matches the guide: %+v", result)
	}
}

func TestAnalyzeEnforcesFileLimit(t *testing.T) {
	_, err := Analyze(bytes.NewReader(make([]byte, MaxFileBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "20 MiB") {
		t.Fatalf("oversized HAR was not rejected: %v", err)
	}
}
