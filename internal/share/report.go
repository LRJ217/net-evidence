// Package share turns local diagnostic evidence into a deliberately limited
// report suitable for review before it is sent to someone else.
package share

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Report struct {
	SchemaVersion int               `json:"schema_version"`
	PrivacyNote   string            `json:"privacy_note"`
	Evidence      diagnostic.Result `json:"evidence"`
	Findings      []Finding         `json:"findings"`
}

const privacyNote = "分享版已省略 URL 路径与查询、IP、MAC、代理详情、证书名称及原始错误文本；发送前仍请预览。"

// Build projects known-safe fields into a new value. Avoid JSON round trips or
// reflection here: newly added raw evidence must be explicitly reviewed before
// it can appear in a shared report.
func Build(raw diagnostic.Result) Report {
	return Report{
		SchemaVersion: 1,
		PrivacyNote:   privacyNote,
		Evidence:      sanitize(raw),
		Findings:      Analyze(raw),
	}
}

func Analyze(r diagnostic.Result) []Finding {
	findings := []Finding{}
	add := func(id, title, explanation string, evidence ...string) {
		findings = append(findings, Finding{id, title, explanation, evidence})
	}
	if r.DNS.Status == diagnostic.StatusFailure {
		add("dns_failure", "域名解析失败", "可能是域名错误、DNS 配置或解析服务异常；需要结合其他网络信息确认。", "dns")
	}
	if r.TCP.Status == diagnostic.StatusFailure {
		switch errorKind(r.TCP.Error) {
		case "connection_refused":
			add("tcp_refused", "目标端口拒绝连接", "目标主机可达但该端口可能没有服务监听，或连接被主动拒绝。", "tcp")
		case "timeout", "network_unreachable":
			add("tcp_unreachable", "无法建立 TCP 连接", "可能与网络路径、防火墙或目标服务有关；单次探测无法定位具体节点。", "tcp")
		default:
			add("tcp_failure", "TCP 连接失败", "连接失败的具体原因仍需结合本机和目标环境检查。", "tcp")
		}
	}
	if r.TLS.Status == diagnostic.StatusFailure {
		if errorKind(r.TLS.Error) == "certificate_invalid" && r.TLS.Data != nil {
			switch {
			case !r.TLS.Data.TimeValid:
				add("certificate_time", "证书有效期检查失败", "可能是服务端证书过期、尚未生效，或本机时间异常。", "tls")
			case !r.TLS.Data.HostnameValid:
				add("certificate_name", "证书域名不匹配", "服务端证书可能不适用于请求的主机名。", "tls")
			default:
				add("certificate_trust", "证书信任验证失败", "可能是证书链不完整或签发机构不受本机信任。", "tls")
			}
		} else {
			add("tls_failure", "TLS 握手失败", "可能与服务端 TLS 配置、证书或网络中断有关。", "tls")
		}
	}
	if r.HTTP.Status == diagnostic.StatusFailure {
		if errorKind(r.HTTP.Error) == "redirect_limit" {
			add("redirect_limit", "重定向次数超出限制", "站点可能存在循环跳转，或跳转链超过本次诊断的上限。", "http")
		} else {
			add("http_failure", "HTTP 请求未完成", "底层连接已建立，但 HTTP 响应未能完整取得。", "http")
		}
	} else if r.HTTP.Status == diagnostic.StatusSuccess && r.HTTP.Data != nil {
		switch {
		case r.HTTP.Data.StatusCode >= 500:
			add("http_server_error", "服务端返回 5xx", "网络请求到达服务端，但服务端或上游服务可能发生错误。", "http")
		case r.HTTP.Data.StatusCode >= 400:
			add("http_client_error", "服务端返回 4xx", "网络请求到达服务端；请检查地址、权限或接口要求。", "http")
		}
	}
	if r.Environment.Data != nil && r.Environment.Data.Proxy.Enabled && !isLoopbackTarget(r.Target.Host) &&
		(r.TCP.Status == diagnostic.StatusFailure || r.HTTP.Status == diagnostic.StatusFailure) {
		add("proxy_path", "直连探测与代理访问可能不同", "本机配置了系统代理，而本次网络探测使用直连；浏览器经代理访问时结果可能不同。", "environment", "tcp", "http")
	}
	if len(findings) == 0 {
		add("no_obvious_failure", "未发现明确故障", "本次探测未发现可直接归因的失败；间歇性问题仍可能需要再次采样。", "dns", "tcp", "tls", "http")
	}
	return findings
}

func isLoopbackTarget(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func errorKind(err *diagnostic.ProbeError) string {
	if err == nil {
		return ""
	}
	return err.Kind
}

func sanitize(r diagnostic.Result) diagnostic.Result {
	urlValue := safeURL(r.Target.URL)
	host := safeHost(r.Target.Host)
	port := safePort(r.Target.Port)
	version := "unknown"
	if r.ToolVersion == diagnostic.ToolVersion {
		version = r.ToolVersion
	}
	out := diagnostic.Result{
		SchemaVersion: r.SchemaVersion,
		ToolVersion:   version,
		StartedAt:     r.StartedAt,
		DurationMs:    r.DurationMs,
		Target: diagnostic.Target{
			Input: urlValue, URL: urlValue, Scheme: safeScheme(r.Target.Scheme),
			Host: host, Port: port, Address: net.JoinHostPort(host, port),
		},
		DNS:         cleanStep(r.DNS, "dns"),
		TCP:         cleanStep(r.TCP, "tcp"),
		TLS:         cleanStep(r.TLS, "tls"),
		HTTP:        cleanStep(r.HTTP, "http"),
		Environment: cleanStep(r.Environment, "environment"),
	}
	if r.DNS.Data != nil {
		out.DNS.Data = &diagnostic.DNSData{IPv4: maskList(r.DNS.Data.IPv4, "[IP_REDACTED]"), IPv6: maskList(r.DNS.Data.IPv6, "[IP_REDACTED]")}
	}
	if r.TCP.Data != nil {
		out.TCP.Data = &diagnostic.TCPData{ConnectedAddress: "[ADDRESS_REDACTED]"}
	}
	if d := r.TLS.Data; d != nil {
		out.TLS.Data = &diagnostic.TLSData{
			Protocol: safeTLSVersion(d.Protocol), CipherSuite: safeCipherSuite(d.CipherSuite), HandshakeMs: d.HandshakeMs,
			Certificate: diagnostic.CertificateData{
				Subject: "[CERT_NAME_REDACTED]", Issuer: "[CERT_NAME_REDACTED]",
				DNSNames:  maskList(d.Certificate.DNSNames, "[CERT_NAME_REDACTED]"),
				NotBefore: d.Certificate.NotBefore, NotAfter: d.Certificate.NotAfter,
			},
			HostnameValid: d.HostnameValid, TimeValid: d.TimeValid, Verified: d.Verified,
		}
		if d.VerifyError != "" {
			out.TLS.Data.VerifyError = "[ERROR_REDACTED]"
		}
	}
	if d := r.HTTP.Data; d != nil {
		hops := make([]diagnostic.HTTPHop, 0, len(d.Hops))
		for _, hop := range d.Hops {
			hops = append(hops, diagnostic.HTTPHop{URL: safeURL(hop.URL), StatusCode: hop.StatusCode, DurationMs: hop.DurationMs})
		}
		transport := "unknown"
		if d.Transport == "direct" {
			transport = "direct"
		}
		out.HTTP.Data = &diagnostic.HTTPData{StatusCode: d.StatusCode, FinalURL: safeURL(d.FinalURL), Hops: hops, Transport: transport}
	}
	if d := r.Environment.Data; d != nil {
		proxy := diagnostic.ProxyData{Enabled: d.Proxy.Enabled, EnvPresent: d.Proxy.EnvPresent}
		if d.Proxy.Server != "" {
			proxy.Server = "[PROXY_REDACTED]"
		}
		if d.Proxy.AutoConfigURL != "" {
			proxy.AutoConfigURL = "[PROXY_REDACTED]"
		}
		interfaces := make([]diagnostic.InterfaceData, 0, len(d.Interfaces))
		for i, item := range d.Interfaces {
			entry := diagnostic.InterfaceData{Name: fmt.Sprintf("interface-%d", i+1), Addresses: maskList(item.Addresses, "[ADDRESS_REDACTED]")}
			if item.MAC != "" {
				entry.MAC = "[MAC_REDACTED]"
			}
			interfaces = append(interfaces, entry)
		}
		out.Environment.Data = &diagnostic.EnvironmentData{Proxy: proxy, Interfaces: interfaces}
		if d.ProxyError != "" {
			out.Environment.Data.ProxyError = "[ERROR_REDACTED]"
		}
	}
	return out
}

func cleanStep[T any](step diagnostic.Step[T], id string) diagnostic.Step[T] {
	out := diagnostic.Step[T]{ID: id, Status: diagnostic.Status(safeStatus(step.Status)), DurationMs: step.DurationMs}
	if step.Error != nil {
		out.Error = &diagnostic.ProbeError{Kind: safeErrorKind(step.Error.Kind), Message: "[ERROR_REDACTED]"}
	}
	if step.Reason != "" {
		out.Reason = "依赖步骤未完成或目标不适用"
	}
	return out
}

func safeErrorKind(kind string) string {
	switch kind {
	case "canceled", "timeout", "dns_not_found", "dns_no_addresses", "connection_refused", "network_unreachable", "certificate_missing", "certificate_invalid", "tls_handshake_failed", "redirect_limit", "unknown":
		return kind
	default:
		return "other"
	}
}

func maskList(values []string, marker string) []string {
	out := make([]string, len(values))
	for i := range out {
		out[i] = marker
	}
	return out
}

func safeScheme(scheme string) string {
	if scheme == "http" || scheme == "https" {
		return scheme
	}
	return "https"
}

func safePort(port string) string {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "0"
	}
	return strconv.Itoa(number)
}

func safeTLSVersion(value string) string {
	switch value {
	case "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3":
		return value
	default:
		return "unknown"
	}
}

func safeCipherSuite(value string) string {
	for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if suite.Name == value {
			return value
		}
	}
	return "unknown"
}

func safeHost(host string) string {
	if net.ParseIP(host) != nil {
		return "[IP_REDACTED]"
	}
	// Hostnames from NormalizeTarget are IDNA ASCII. Reject arbitrary future data.
	if host == "" || strings.ContainsAny(host, "/\\?#@ ") {
		return "[HOST_REDACTED]"
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return "[HOST_REDACTED]"
		}
	}
	return host
}

func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "[URL_REDACTED]"
	}
	host := safeHost(u.Hostname())
	port := u.Port()
	if port != "" && safePort(port) == "0" {
		return "[URL_REDACTED]"
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	result := u.Scheme + "://" + host + "/"
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		result += "[PATH_REDACTED]"
	}
	if u.RawQuery != "" || u.ForceQuery {
		result += "?[QUERY_REDACTED]"
	}
	return result
}
