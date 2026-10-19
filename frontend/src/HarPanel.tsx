import { dateText, statusText } from './EvidencePanel'
import type { HarAnalysis, HarResource, HistorySummary, Report } from './types'
import './har.css'

const issueText: Record<string, string> = {
  no_response: '无 HTTP 响应', server_error: 'HTTP 5xx 响应',
  client_error: 'HTTP 4xx 响应', slow: '耗时较长',
}
const kindText: Record<string, string> = {
  document: '网页', script: '脚本', style: '样式', image: '图片',
  font: '字体', api: '接口/JSON', media: '音视频', other: '其他',
}

function phases(row: HarResource) {
  return ([['DNS', row.dns_ms], ['连接', row.connect_ms], ['TLS', row.tls_ms],
    ['等待', row.wait_ms], ['接收', row.receive_ms]] as const)
    .filter(([, ms]) => ms && ms > 0).map(([label, ms]) => `${label} ${ms}ms`).join(' · ') || '无阶段耗时'
}

interface Props {
  analysis: HarAnalysis | null
  importing: boolean
  onImport: () => void
  history: HistorySummary[]
  diagnosticId: string
  onDiagnostic: (id: string) => void
  diagnostic: Report | null
  diagnosticLoading: boolean
}

export function HarPanel({ analysis, importing, onImport, history, diagnosticId, onDiagnostic, diagnostic, diagnosticLoading }: Props) {
  const matched = analysis && diagnostic && analysis.main_host && diagnostic.evidence.target.host &&
    !analysis.main_host.startsWith('[') && analysis.main_host.toLowerCase() === diagnostic.evidence.target.host.toLowerCase()
  const minutesApart = analysis?.capture_started_at && diagnostic?.evidence.started_at
    ? Math.round(Math.abs(Date.parse(analysis.capture_started_at) - Date.parse(diagnostic.evidence.started_at)) / 60000) : null
  const problemCount = analysis ? analysis.no_response + analysis.http_errors : 0
  return <>
    <div className="page-intro"><div className="eyebrow"><span className="eyebrow-line" /> BROWSER EVIDENCE</div><h1>找到网页加载失败的请求。</h1><p>导入浏览器导出的 HAR 文件，查看失败请求、慢请求和涉及的主机；可与本机诊断记录并排查看。</p></div>
    <section className="panel har-import-panel">
      <div className="panel-heading"><div><div className="eyebrow small">LOCAL HAR ANALYSIS</div><h2>浏览器记录</h2></div><button className="primary-button" disabled={importing} onClick={onImport}>{importing ? '正在分析…' : '选择 HAR 文件'} <span>↗</span></button></div>
      <p className="batch-note">仅在本机读取，最大 20 MiB；不保存 HAR 或分析结果。请求头、Cookie、请求体、响应体和 URL 路径及查询值不会进入界面。建议从浏览器导出已清理敏感信息的 HAR，分享原文件前仍需自行检查。</p>
    </section>
    {!analysis ? <div className="empty-results"><div className="empty-symbol">⌁</div><h2>尚未导入浏览器记录</h2><p>在浏览器开发者工具的“网络”面板录制问题，再导出 HAR 文件。</p></div> : <>
      <section className="panel har-summary-panel">
        <div className="panel-heading"><div><div className="eyebrow small">CAPTURE SUMMARY</div><h2>本次加载概况</h2></div><span className="section-meta">{analysis.capture_started_at ? dateText(analysis.capture_started_at) : '未记录开始时间'}</span></div>
        <p className="batch-note">推定页面主机：{analysis.main_host || '无法识别'} · 其他主机请求 {analysis.other_host_requests} 条 · 已忽略非 HTTP(S) 或无效请求 {analysis.ignored_entries} 条。页面主机取首个 HTML 请求；缺少 HTML 时取首条 HTTP(S) 请求。</p>
        <div className="batch-stats"><div><strong>{analysis.supported_entries}</strong><small>HTTP(S) 请求</small></div><div><strong>{analysis.no_response}</strong><small>无 HTTP 响应</small></div><div><strong>{analysis.http_errors}</strong><small>4xx / 5xx</small></div><div><strong>{analysis.slow}</strong><small>耗时 ≥ 3 秒</small></div></div>
        {analysis.document_ok && problemCount > 0 && <p className="batch-highlight">首个 HTML 文档取得正常响应，但部分资源或接口出现异常。这可能解释“网页能打开，功能却不能用”。</p>}
        <p className="comparison-note">“无 HTTP 响应”也可能包含浏览器主动取消、拦截或 HAR 记录不完整；4xx 也可能是预期的权限响应。它们都不能单独证明网络故障。耗时来自浏览器记录，和本机诊断不一定使用相同连接路径。</p>
      </section>
      <section className="panel har-host-panel"><div className="panel-heading"><div><div className="eyebrow small">HOSTS</div><h2>涉及的主机</h2></div><span className="section-meta">按异常数排序，最多 12 个</span></div>
        <div className="table-scroll"><table><thead><tr><th>主机</th><th>请求</th><th>无响应或错误</th><th>慢请求</th></tr></thead><tbody>{analysis.hosts.map(host => <tr key={host.host}><td>{host.host}</td><td>{host.requests}</td><td className={host.problems ? 'changed' : ''}>{host.problems}</td><td>{host.slow}</td></tr>)}</tbody></table></div>
      </section>
      <section className="panel har-requests-panel"><div className="panel-heading"><div><div className="eyebrow small">REQUESTS</div><h2>异常与慢请求</h2></div><span className="section-meta">显示 {analysis.rows.length} 条{analysis.omitted_rows ? `，另有 ${analysis.omitted_rows} 条未显示` : ''}</span></div>
        {analysis.rows.length ? <div className="table-scroll batch-table"><table><thead><tr><th>序号</th><th>录制后</th><th>问题</th><th>类型</th><th>请求</th><th>状态</th><th>耗时</th><th>阶段耗时</th></tr></thead><tbody>{analysis.rows.map(row => <tr key={row.number}><td>#{row.number}</td><td>{(row.offset_ms || 0) / 1000} 秒</td><td className={row.issue === 'slow' ? '' : 'changed'}>{issueText[row.issue] || row.issue}</td><td>{kindText[row.kind] || '其他'}</td><td className="har-url" title={row.url}>{row.method} {row.url}</td><td>{row.status || '—'}</td><td>{row.duration_ms} ms</td><td>{phases(row)}</td></tr>)}</tbody></table></div> : <div className="empty-batch">没有发现 HTTP 错误、无响应或超过 3 秒的请求。</div>}
      </section>
      <section className="panel har-compare-panel"><div className="panel-heading"><div><div className="eyebrow small">LOCAL COMPARISON</div><h2>对照本机诊断</h2></div></div>
        <p className="batch-note">选择同一站点、尽量接近 HAR 录制时间的诊断。两份记录来自不同探测方式，差异只是排查线索。</p>
        <div className="compare-select"><label htmlFor="har-diagnostic">本机历史记录</label><select id="har-diagnostic" value={diagnosticId} onChange={event => onDiagnostic(event.target.value)}><option value="">选择一条诊断记录</option>{history.map(item => <option key={item.id} value={item.id}>{item.target} · {dateText(item.saved_at)}</option>)}</select></div>
        {diagnosticLoading && <p className="comparison-note">正在读取诊断记录…</p>}
        {diagnostic && <><div className="har-correlation"><div><small>推定页面主机</small><strong>{analysis.main_host || '未知'}</strong></div><div><small>本机诊断目标</small><strong>{diagnostic.evidence.target.host}</strong></div><div><small>关联</small><strong>{matched ? '主机一致' : '主机不一致或无法判断'}</strong></div><div><small>采集时间相差</small><strong>{minutesApart !== null && Number.isFinite(minutesApart) ? `${minutesApart} 分钟` : '无法判断'}</strong></div></div>
          <div className="har-layer-list">{([['DNS', diagnostic.evidence.dns.status], ['TCP', diagnostic.evidence.tcp.status], ['TLS', diagnostic.evidence.tls.status], ['HTTP', diagnostic.evidence.http.status], ['代理 HTTP', diagnostic.evidence.proxy_http?.status]] as const).map(([label, status]) => status && <span key={label}>{label}：{statusText[status]}</span>)}</div>
          {matched && diagnostic.evidence.http.status === 'success' && problemCount > 0 && <p className="batch-highlight">本机对主要主机的 HTTP 探测通过，但浏览器记录中仍有失败请求。请优先查看上方出错的资源或接口及其主机。</p>}
          {minutesApart !== null && Number.isFinite(minutesApart) && minutesApart > 30 && <p className="comparison-note">两次记录相隔超过 30 分钟，网络环境可能已变化，结果只能作粗略对照。</p>}
          {diagnostic.evidence.http.data?.status_code ? <p className="comparison-note">诊断 HTTP 状态码：{diagnostic.evidence.http.data.status_code}。浏览器请求与本机探测可能经过不同代理或缓存。</p> : null}
        </>}
      </section>
    </>}
  </>
}
