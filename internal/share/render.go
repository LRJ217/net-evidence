package share

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/LRJ217/net-evidence/internal/diagnostic"
)

func RenderJSON(report Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func RenderHTML(report Report) ([]byte, error) {
	data, err := RenderJSON(report)
	if err != nil {
		return nil, err
	}
	view := struct {
		Report Report
		JSON   string
	}{report, string(data)}
	var output bytes.Buffer
	err = template.Must(template.New("report").Parse(htmlTemplate)).Execute(&output, view)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func RenderIssue(report Report) []byte {
	r := report.Evidence
	var b strings.Builder
	fmt.Fprintf(&b, "# NetEvidence 诊断报告\n\n")
	fmt.Fprintf(&b, "**目标：** `%s`  \n**时间：** %s  \n**工具：** NetEvidence\n\n", r.Target.URL, r.StartedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "> %s\n\n", report.PrivacyNote)
	b.WriteString("## 分层证据\n\n| ID | 状态 | 耗时 (ms) | 错误类别 |\n| --- | --- | ---: | --- |\n")
	writeIssueStep(&b, r.DNS.ID, r.DNS.Status, r.DNS.DurationMs, r.DNS.Error)
	writeIssueStep(&b, r.TCP.ID, r.TCP.Status, r.TCP.DurationMs, r.TCP.Error)
	writeIssueStep(&b, r.TLS.ID, r.TLS.Status, r.TLS.DurationMs, r.TLS.Error)
	writeIssueStep(&b, r.HTTP.ID, r.HTTP.Status, r.HTTP.DurationMs, r.HTTP.Error)
	writeIssueStep(&b, r.Environment.ID, r.Environment.Status, r.Environment.DurationMs, r.Environment.Error)
	b.WriteString("\n## 关键事实\n\n")
	if r.DNS.Data != nil {
		fmt.Fprintf(&b, "- DNS 返回 IPv4 %d 个、IPv6 %d 个。\n", len(r.DNS.Data.IPv4), len(r.DNS.Data.IPv6))
	}
	if r.TLS.Data != nil {
		fmt.Fprintf(&b, "- TLS：证书域名匹配=%t，有效期通过=%t，信任验证通过=%t。\n", r.TLS.Data.HostnameValid, r.TLS.Data.TimeValid, r.TLS.Data.Verified)
	}
	if r.HTTP.Data != nil {
		fmt.Fprintf(&b, "- HTTP：状态码 %d，观察到 %d 跳响应。\n", r.HTTP.Data.StatusCode, len(r.HTTP.Data.Hops))
	}
	if r.Environment.Data != nil {
		fmt.Fprintf(&b, "- 本机环境：代理启用=%t，活动网卡 %d 个。\n", r.Environment.Data.Proxy.Enabled, len(r.Environment.Data.Interfaces))
	}
	b.WriteString("\n## 可能原因（推断）\n\n")
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "- **%s**：%s（依据：`%s`）\n", finding.Title, finding.Explanation, strings.Join(finding.EvidenceIDs, "`, `"))
	}
	return []byte(b.String())
}

func writeIssueStep(b *strings.Builder, id string, status diagnostic.Status, duration int64, probeErr *diagnostic.ProbeError) {
	kind := "—"
	if probeErr != nil {
		kind = safeErrorKind(probeErr.Kind)
	}
	fmt.Fprintf(b, "| %s | %s | %d | %s |\n", id, safeStatus(status), duration, kind)
}

func safeStatus(status diagnostic.Status) string {
	switch status {
	case diagnostic.StatusSuccess, diagnostic.StatusFailure, diagnostic.StatusSkipped, diagnostic.StatusPartial:
		return string(status)
	default:
		return "unknown"
	}
}

const htmlTemplate = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetEvidence 诊断报告</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#17212b}h1,h2{line-height:1.2}aside{background:#fff4dc;padding:1rem;border-left:4px solid #b57200}li{margin:.7rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem;border-radius:8px}code{overflow-wrap:anywhere}</style></head>
<body><h1>NetEvidence 诊断报告</h1><p>目标：<code>{{.Report.Evidence.Target.URL}}</code></p><p>时间：{{.Report.Evidence.StartedAt}}</p>
<aside>{{.Report.PrivacyNote}}</aside><h2>可能原因（推断）</h2><ul>{{range .Report.Findings}}<li><strong>{{.Title}}</strong>：{{.Explanation}}（依据：{{range $i, $id := .EvidenceIDs}}{{if $i}}, {{end}}<code>{{$id}}</code>{{end}}）</li>{{end}}</ul>
<h2>脱敏证据 JSON</h2><pre>{{.JSON}}</pre></body></html>
`
