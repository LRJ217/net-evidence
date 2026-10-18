package history

import (
	"slices"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

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
	Environment     EnvironmentDiff `json:"environment"`
}

// EnvironmentDiff exposes only whether sensitive local settings changed.
type EnvironmentDiff struct {
	Available                bool `json:"available"`
	ProxyEnabledChanged      bool `json:"proxy_enabled_changed"`
	ProxyServerChanged       bool `json:"proxy_server_changed"`
	ProxyBypassChanged       bool `json:"proxy_bypass_changed"`
	PACChanged               bool `json:"pac_changed"`
	EnvProxyPresenceChanged  bool `json:"env_proxy_presence_changed"`
	NetworkInterfacesChanged bool `json:"network_interfaces_changed"`
	DNSAnswersAvailable      bool `json:"dns_answers_available"`
	DNSAnswersChanged        bool `json:"dns_answers_changed"`
}

func Compare(left, right Record) Comparison {
	rows := []ComparisonRow{
		comparisonRow("dns", left.Result.DNS.Status, right.Result.DNS.Status, left.Result.DNS.DurationMs, right.Result.DNS.DurationMs),
		comparisonRow("tcp", left.Result.TCP.Status, right.Result.TCP.Status, left.Result.TCP.DurationMs, right.Result.TCP.DurationMs),
		comparisonRow("tls", left.Result.TLS.Status, right.Result.TLS.Status, left.Result.TLS.DurationMs, right.Result.TLS.DurationMs),
		comparisonRow("http", left.Result.HTTP.Status, right.Result.HTTP.Status, left.Result.HTTP.DurationMs, right.Result.HTTP.DurationMs),
		comparisonRow("environment", left.Result.Environment.Status, right.Result.Environment.Status, left.Result.Environment.DurationMs, right.Result.Environment.DurationMs),
	}
	if left.Result.ProxyHTTP != nil || right.Result.ProxyHTTP != nil {
		leftProxy := diagnostic.Step[diagnostic.HTTPData]{Status: diagnostic.StatusSkipped}
		rightProxy := diagnostic.Step[diagnostic.HTTPData]{Status: diagnostic.StatusSkipped}
		if left.Result.ProxyHTTP != nil {
			leftProxy = *left.Result.ProxyHTTP
		}
		if right.Result.ProxyHTTP != nil {
			rightProxy = *right.Result.ProxyHTTP
		}
		rows = append(rows, comparisonRow("proxy_http", leftProxy.Status, rightProxy.Status, leftProxy.DurationMs, rightProxy.DurationMs))
	}
	result := Comparison{Left: summarize(left), Right: summarize(right), Rows: rows,
		Environment: compareEnvironment(left.Result, right.Result)}
	if left.Result.HTTP.Data != nil {
		result.LeftHTTPStatus = left.Result.HTTP.Data.StatusCode
	}
	if right.Result.HTTP.Data != nil {
		result.RightHTTPStatus = right.Result.HTTP.Data.StatusCode
	}
	return result
}

func compareEnvironment(left, right diagnostic.Result) EnvironmentDiff {
	diff := EnvironmentDiff{}
	if a, b := left.Environment.Data, right.Environment.Data; a != nil && b != nil {
		diff.Available = true
		diff.ProxyEnabledChanged = a.Proxy.Enabled != b.Proxy.Enabled
		diff.ProxyServerChanged = a.Proxy.Server != b.Proxy.Server
		diff.ProxyBypassChanged = a.Proxy.BypassList != b.Proxy.BypassList
		diff.PACChanged = a.Proxy.AutoConfigURL != b.Proxy.AutoConfigURL
		diff.EnvProxyPresenceChanged = a.Proxy.EnvPresent != b.Proxy.EnvPresent
		diff.NetworkInterfacesChanged = !slices.Equal(interfaceKeys(a.Interfaces), interfaceKeys(b.Interfaces))
	}
	if a, b := left.DNS.Data, right.DNS.Data; a != nil && b != nil && left.Target.Host == right.Target.Host {
		diff.DNSAnswersAvailable = true
		diff.DNSAnswersChanged = !slices.Equal(sortedCopy(append(append([]string{}, a.IPv4...), a.IPv6...)),
			sortedCopy(append(append([]string{}, b.IPv4...), b.IPv6...)))
	}
	return diff
}

func interfaceKeys(items []diagnostic.InterfaceData) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, item.Name+"\x00"+item.MAC+"\x00"+joinSorted(item.Addresses))
	}
	return sortedCopy(keys)
}

func joinSorted(values []string) string {
	values = sortedCopy(values)
	result := ""
	for _, value := range values {
		result += "\x00" + value
	}
	return result
}

func sortedCopy(values []string) []string {
	return slices.Sorted(slices.Values(values))
}

func comparisonRow(id string, left, right diagnostic.Status, leftMs, rightMs int64) ComparisonRow {
	return ComparisonRow{ID: id, LeftStatus: left, RightStatus: right,
		LeftDurationMs: leftMs, RightDurationMs: rightMs, DeltaMs: rightMs - leftMs, Changed: left != right}
}
