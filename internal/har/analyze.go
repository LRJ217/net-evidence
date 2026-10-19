// Package har reads a browser HAR file and returns only a limited, redacted
// analysis. The original HAR is never included in the result.
package har

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/LRJ217/net-evidence/internal/share"
)

const (
	MaxFileBytes = 20 << 20
	maxEntries   = 20000
	maxRows      = 200
	maxHosts     = 12
	slowMs       = 3000
)

type Analysis struct {
	SchemaVersion     int           `json:"schema_version"`
	CaptureStartedAt  string        `json:"capture_started_at,omitempty"`
	MainHost          string        `json:"main_host,omitempty"`
	TotalEntries      int           `json:"total_entries"`
	SupportedEntries  int           `json:"supported_entries"`
	IgnoredEntries    int           `json:"ignored_entries"`
	NoResponse        int           `json:"no_response"`
	HTTPErrors        int           `json:"http_errors"`
	Slow              int           `json:"slow"`
	DocumentOK        bool          `json:"document_ok"`
	OtherHostRequests int           `json:"other_host_requests"`
	Rows              []Resource    `json:"rows"`
	OmittedRows       int           `json:"omitted_rows"`
	Hosts             []HostSummary `json:"hosts"`
}

type Resource struct {
	Number     int    `json:"number"`
	URL        string `json:"url"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Kind       string `json:"kind"`
	Issue      string `json:"issue"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	OffsetMs   int64  `json:"offset_ms,omitempty"`
	DNSMs      int64  `json:"dns_ms,omitempty"`
	ConnectMs  int64  `json:"connect_ms,omitempty"`
	TLSMs      int64  `json:"tls_ms,omitempty"`
	WaitMs     int64  `json:"wait_ms,omitempty"`
	ReceiveMs  int64  `json:"receive_ms,omitempty"`
}

type HostSummary struct {
	Host     string `json:"host"`
	Requests int    `json:"requests"`
	Problems int    `json:"problems"`
	Slow     int    `json:"slow"`
}

type file struct {
	Log *struct {
		Entries []entry `json:"entries"`
	} `json:"log"`
}

type entry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Time            float64 `json:"time"`
	ResourceType    string  `json:"_resourceType"`
	Request         struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			MimeType string `json:"mimeType"`
		} `json:"content"`
	} `json:"response"`
	Timings struct {
		DNS     float64 `json:"dns"`
		Connect float64 `json:"connect"`
		SSL     float64 `json:"ssl"`
		Wait    float64 `json:"wait"`
		Receive float64 `json:"receive"`
	} `json:"timings"`
}

// Analyze accepts at most 20 MiB. It never returns raw HAR fields, even for
// malformed input. Status zero means no HTTP response was recorded, which may
// include browser cancellation and is not proof of a network outage.
func Analyze(reader io.Reader) (Analysis, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
	if err != nil {
		return Analysis{}, errors.New("无法读取 HAR 文件")
	}
	if len(data) > MaxFileBytes {
		return Analysis{}, fmt.Errorf("HAR 文件不能超过 %d MiB", MaxFileBytes>>20)
	}
	var input file
	if json.Unmarshal(data, &input) != nil || input.Log == nil || input.Log.Entries == nil {
		return Analysis{}, errors.New("文件不是有效的 HAR 记录")
	}
	if len(input.Log.Entries) > maxEntries {
		return Analysis{}, fmt.Errorf("HAR 请求数不能超过 %d 条", maxEntries)
	}

	result := Analysis{SchemaVersion: 1, TotalEntries: len(input.Log.Entries), Rows: []Resource{}, Hosts: []HostSummary{}}
	var captureStart time.Time
	for _, item := range input.Log.Entries {
		parsed, err := url.Parse(item.Request.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" ||
			share.RedactURL(item.Request.URL) == "[URL_REDACTED]" {
			continue
		}
		if started, err := time.Parse(time.RFC3339Nano, item.StartedDateTime); err == nil && (captureStart.IsZero() || started.Before(captureStart)) {
			captureStart = started
		}
	}
	if !captureStart.IsZero() {
		result.CaptureStartedAt = captureStart.UTC().Format(time.RFC3339Nano)
	}

	hosts := map[string]*HostSummary{}
	allProblems := []Resource{}
	firstHost := ""
	for index, item := range input.Log.Entries {
		parsed, err := url.Parse(item.Request.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
			result.IgnoredEntries++
			continue
		}
		host := share.RedactHost(parsed.Hostname())
		if !strings.HasPrefix(host, "[") {
			host = strings.ToLower(host)
		}
		safeURL := share.RedactURL(item.Request.URL)
		if safeURL == "[URL_REDACTED]" {
			result.IgnoredEntries++
			continue
		}
		result.SupportedEntries++
		if firstHost == "" {
			firstHost = host
		}
		kind := resourceKind(item.Response.Content.MimeType, item.ResourceType, parsed.Path)
		if kind == "document" && result.MainHost == "" {
			result.MainHost = host
			result.DocumentOK = item.Response.Status >= 200 && item.Response.Status < 400
		}
		status := safeStatus(item.Response.Status)
		duration := milliseconds(item.Time)
		issue := issueKind(status, duration)
		if status == 0 {
			result.NoResponse++
		} else if status >= 400 {
			result.HTTPErrors++
		}
		if duration >= slowMs {
			result.Slow++
		}
		group := hosts[host]
		if group == nil {
			group = &HostSummary{Host: host}
			hosts[host] = group
		}
		group.Requests++
		if status == 0 || status >= 400 {
			group.Problems++
		}
		if duration >= slowMs {
			group.Slow++
		}
		if issue == "" {
			continue
		}
		row := Resource{Number: index + 1, URL: safeURL, Host: host,
			Method: safeMethod(item.Request.Method), Kind: kind, Issue: issue,
			Status: status, DurationMs: duration,
			DNSMs: milliseconds(item.Timings.DNS), ConnectMs: milliseconds(item.Timings.Connect),
			TLSMs: milliseconds(item.Timings.SSL), WaitMs: milliseconds(item.Timings.Wait),
			ReceiveMs: milliseconds(item.Timings.Receive)}
		if started, err := time.Parse(time.RFC3339Nano, item.StartedDateTime); err == nil && !captureStart.IsZero() {
			row.OffsetMs = milliseconds(float64(started.Sub(captureStart).Milliseconds()))
		}
		allProblems = append(allProblems, row)
	}
	if result.MainHost == "" {
		result.MainHost = firstHost
	}
	for host, group := range hosts {
		if host != result.MainHost {
			result.OtherHostRequests += group.Requests
		}
		result.Hosts = append(result.Hosts, *group)
	}
	slices.SortFunc(result.Hosts, func(a, b HostSummary) int {
		if a.Problems != b.Problems {
			return b.Problems - a.Problems
		}
		if a.Requests != b.Requests {
			return b.Requests - a.Requests
		}
		return strings.Compare(a.Host, b.Host)
	})
	if len(result.Hosts) > maxHosts {
		result.Hosts = result.Hosts[:maxHosts]
	}
	slices.SortFunc(allProblems, func(a, b Resource) int {
		if issueRank(a.Issue) != issueRank(b.Issue) {
			return issueRank(a.Issue) - issueRank(b.Issue)
		}
		return a.Number - b.Number
	})
	if len(allProblems) > maxRows {
		result.OmittedRows = len(allProblems) - maxRows
		allProblems = allProblems[:maxRows]
	}
	result.Rows = allProblems
	return result, nil
}

func milliseconds(value float64) int64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 {
		return 0
	}
	return int64(math.Round(math.Min(value, 24*60*60*1000)))
}

func safeStatus(value int) int {
	if value >= 100 && value <= 599 {
		return value
	}
	return 0
}

func issueKind(status int, duration int64) string {
	switch {
	case status == 0:
		return "no_response"
	case status >= 500:
		return "server_error"
	case status >= 400:
		return "client_error"
	case duration >= slowMs:
		return "slow"
	default:
		return ""
	}
}

func issueRank(value string) int {
	switch value {
	case "no_response":
		return 0
	case "server_error":
		return 1
	case "client_error":
		return 2
	default:
		return 3
	}
}

func safeMethod(value string) string {
	switch strings.ToUpper(value) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return strings.ToUpper(value)
	default:
		return "OTHER"
	}
}

func resourceKind(mime, browserType, requestPath string) string {
	mime = strings.ToLower(strings.TrimSpace(strings.Split(mime, ";")[0]))
	switch {
	case mime == "text/html" || mime == "application/xhtml+xml":
		return "document"
	case strings.Contains(mime, "javascript"):
		return "script"
	case mime == "text/css":
		return "style"
	case strings.HasPrefix(mime, "image/"):
		return "image"
	case strings.HasPrefix(mime, "font/") || strings.Contains(mime, "font"):
		return "font"
	case mime == "application/json" || strings.HasSuffix(mime, "+json"):
		return "api"
	case strings.HasPrefix(mime, "audio/") || strings.HasPrefix(mime, "video/"):
		return "media"
	}
	switch strings.ToLower(browserType) {
	case "document", "script", "image", "font", "media":
		return strings.ToLower(browserType)
	case "stylesheet":
		return "style"
	case "xhr", "fetch":
		return "api"
	}
	path := strings.ToLower(requestPath)
	switch {
	case strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs"):
		return "script"
	case strings.HasSuffix(path, ".css"):
		return "style"
	case strings.HasSuffix(path, ".png") || strings.HasSuffix(path, ".jpg") ||
		strings.HasSuffix(path, ".jpeg") || strings.HasSuffix(path, ".webp") ||
		strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".gif"):
		return "image"
	case strings.HasSuffix(path, ".woff") || strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ttf"):
		return "font"
	default:
		return "other"
	}
}
