package history

import "github.com/LRJ217/net-evidence/internal/diagnostic"

type ComparisonRow struct {
	ID              string            `json:"id"`
	LeftStatus      diagnostic.Status `json:"left_status"`
	RightStatus     diagnostic.Status `json:"right_status"`
	LeftDurationMs  int64             `json:"left_duration_ms"`
	RightDurationMs int64             `json:"right_duration_ms"`
	DeltaMs         int64             `json:"delta_ms"`
	Changed         bool              `json:"changed"`
}

type Comparison struct {
	Left            Summary         `json:"left"`
	Right           Summary         `json:"right"`
	Rows            []ComparisonRow `json:"rows"`
	LeftHTTPStatus  int             `json:"left_http_status"`
	RightHTTPStatus int             `json:"right_http_status"`
}

func Compare(left, right Record) Comparison {
	rows := []ComparisonRow{
		comparisonRow("dns", left.Result.DNS.Status, right.Result.DNS.Status, left.Result.DNS.DurationMs, right.Result.DNS.DurationMs),
		comparisonRow("tcp", left.Result.TCP.Status, right.Result.TCP.Status, left.Result.TCP.DurationMs, right.Result.TCP.DurationMs),
		comparisonRow("tls", left.Result.TLS.Status, right.Result.TLS.Status, left.Result.TLS.DurationMs, right.Result.TLS.DurationMs),
		comparisonRow("http", left.Result.HTTP.Status, right.Result.HTTP.Status, left.Result.HTTP.DurationMs, right.Result.HTTP.DurationMs),
		comparisonRow("environment", left.Result.Environment.Status, right.Result.Environment.Status, left.Result.Environment.DurationMs, right.Result.Environment.DurationMs),
	}
	result := Comparison{Left: summarize(left), Right: summarize(right), Rows: rows}
	if left.Result.HTTP.Data != nil {
		result.LeftHTTPStatus = left.Result.HTTP.Data.StatusCode
	}
	if right.Result.HTTP.Data != nil {
		result.RightHTTPStatus = right.Result.HTTP.Data.StatusCode
	}
	return result
}

func comparisonRow(id string, left, right diagnostic.Status, leftMs, rightMs int64) ComparisonRow {
	return ComparisonRow{ID: id, LeftStatus: left, RightStatus: right,
		LeftDurationMs: leftMs, RightDurationMs: rightMs, DeltaMs: rightMs - leftMs, Changed: left != right}
}
