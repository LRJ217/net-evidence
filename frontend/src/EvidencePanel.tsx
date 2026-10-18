import { useState } from 'react'
import type { Evidence, Format, HistorySummary, Report, Status, Step, TCPData } from './types'

export const layers = [
  { id: 'dns', label: 'DNS', subtitle: '解析目标地址' },
  { id: 'tcp', label: 'TCP', subtitle: '建立端口连接' },
  { id: 'tls', label: 'TLS', subtitle: '验证证书与握手' },
  { id: 'http', label: 'HTTP', subtitle: '检查服务响应' },
  { id: 'environment', label: '本机环境', subtitle: '代理与网卡信息' },
  { id: 'proxy_http', label: '代理访问', subtitle: '经系统手动代理请求' },
] as const

export const statusText: Record<Status | 'pending' | 'canceled', string> = {
  success: '通过', failure: '失败', partial: '部分完成', skipped: '跳过', pending: '等待中', canceled: '已取消',
}
const outcomeText: Record<string, string> = { success: '直连可访问', failure: '有故障', attention: '需关注', partial: '未完成', proxy_accessible: '代理可访问', proxy_failure: '代理路径失败' }
const formatText: Record<Format, string> = { json: 'JSON', html: 'HTML', issue: 'Issue Markdown' }

export function dateText(value: string) { return new Date(value).toLocaleString('zh-CN', { hour12: false }) }

function evidenceStep(evidence: Evidence, id: string): Step {
  return (evidence[id as keyof Evidence] as Step | undefined) ?? { id, status: 'skipped', duration_ms: 0, reason: '旧记录未采集此路径' }
}

const proxyReason: Record<string, string> = {
  local_target: '本机目标无需经系统代理探测',
  proxy_disabled: '系统手动代理未启用',
  pac_unsupported: '检测到 PAC 自动配置；当前无法执行其中的规则',
  manual_proxy_unavailable: '没有适用于此目标的手动代理地址',
  manual_proxy_invalid: '系统手动代理地址格式无法识别',
}

function factsFor(id: string, step: Step): string[] {
  const d = step.data as Record<string, unknown> | undefined
  if (!d) return step.reason ? [proxyReason[step.reason] ?? step.reason] : []
  if (id === 'dns') return [...(step.reason === 'literal_ip' ? ['字面量 IP，无需域名解析'] : []), `IPv4：${(d.ipv4 as string[] | undefined)?.length ?? 0} 个`, `IPv6：${(d.ipv6 as string[] | undefined)?.length ?? 0} 个`]
  if (id === 'tcp') return step.status === 'success' ? ['至少一个探测地址建立了连接'] : []
  if (id === 'tls') return [
    `协议：${String(d.protocol ?? '未知')}`,
    `证书域名：${d.hostname_valid ? '匹配' : '未通过'}`,
    `证书时间：${d.time_valid ? '有效' : '未通过'}`,
    `信任验证：${d.verified ? '通过' : '未通过'}`,
  ]
  if (id === 'http' || id === 'proxy_http') return [`状态码：${String(d.status_code ?? '—')}`, `响应跳数：${(d.hops as unknown[] | undefined)?.length ?? 0}`]
  if (id === 'environment') {
    const proxy = d.proxy as { enabled?: boolean } | undefined
    return [`系统代理：${proxy?.enabled ? '已启用' : '未启用'}`, `活动网卡：${(d.interfaces as unknown[] | undefined)?.length ?? 0} 个`]
  }
  return []
}

interface Props {
  report: Report | null
  localTCP: TCPData | null
  busy: boolean
  progress: Record<string, { status: Status; duration_ms: number }>
  selectedSummary?: HistorySummary
  selectedId: string
  format: Format
  preview: string
  onFormat: (format: Format) => void
  onExport: () => void
  onCopy: () => void
}

export function EvidencePanel({ report, localTCP, busy, progress, selectedSummary, selectedId, format, preview, onFormat, onExport, onCopy }: Props) {
  const [selectedLayer, setSelectedLayer] = useState<string>('dns')
  const finished = Object.keys(progress).length
  return <>
    <div className="section-heading"><div><div className="eyebrow small">LIVE EVIDENCE</div><h2>分层证据</h2></div><span className="section-meta">{busy ? `已完成 ${finished} / ${layers.length} 层` : report ? `耗时 ${report.evidence.duration_ms} ms` : '等待开始'}</span></div>
    <div className="layer-grid">{layers.map((layer, index) => {
      const step = report ? evidenceStep(report.evidence, layer.id) : progress[layer.id]
      const errorKind = report && step ? (step as Step).error?.kind : undefined
      const status = errorKind === 'canceled' ? 'canceled' : step?.status ?? 'pending'
      const details = report && step ? factsFor(layer.id, step as Step) : []
      if (layer.id === 'tcp' && localTCP?.attempts?.length) {
        details.push(...localTCP.attempts.map(attempt => `${attempt.family} 首个地址 ${attempt.address}：${attempt.error?.kind === 'canceled' ? '已取消' : statusText[attempt.status]} · ${attempt.duration_ms} ms${attempt.error && attempt.error.kind !== 'canceled' ? ` (${attempt.error.kind})` : ''}`))
      }
      return <article className={`layer-card ${status}`} key={layer.id}>
        <div className="layer-top"><span className="layer-index">{String(index + 1).padStart(2, '0')}</span><span className={`status-pill ${status}`}>{statusText[status]}</span></div>
        <h3>{layer.label}</h3><p>{layer.subtitle}</p>
        {step && <div className="layer-duration">{step.duration_ms} ms</div>}
        {details.length > 0 && <ul>{details.map((fact, i) => <li key={i}>{fact}</li>)}</ul>}
        {errorKind && errorKind !== 'canceled' && <div className="error-kind">{errorKind}</div>}
        {layer.id === 'tcp' && localTCP?.attempts?.length ? <div className="local-only">IP 仅在本机显示，分享报告会隐藏</div> : null}
      </article>
    })}</div>
    {report ? <>
      <details className="panel detail-panel"><summary>分层详情 <span>查看已脱敏的结构化证据</span></summary><div className="detail-tabs">{layers.map(layer => <button key={layer.id} className={selectedLayer === layer.id ? 'selected' : ''} onClick={() => setSelectedLayer(layer.id)}>{layer.label}</button>)}</div><pre>{JSON.stringify(evidenceStep(report.evidence, selectedLayer), null, 2)}</pre></details>
      <div className="results-grid">
        <section className="panel findings-panel"><div className="panel-heading"><div><div className="eyebrow small">INTERPRETATION</div><h2>可能原因</h2></div><span className="panel-count">{report.findings.length} 条推断</span></div><div className="findings-list">{report.findings.map(finding => <article key={finding.id}><div className="finding-marker">?</div><div><h3>{finding.title}</h3><p>{finding.explanation}</p><small>依据：{finding.evidence_ids.map(id => <code key={id}>{id}</code>)}</small></div></article>)}</div></section>
        <section className="panel snapshot-panel"><div className="eyebrow small">SNAPSHOT</div><h2>本次诊断</h2><dl><div><dt>目标</dt><dd title={report.evidence.target.url}>{report.evidence.target.url}</dd></div><div><dt>开始时间</dt><dd>{dateText(report.evidence.started_at)}</dd></div><div><dt>记录</dt><dd>{selectedSummary ? outcomeText[selectedSummary.outcome] ?? selectedSummary.outcome : '未保存'}</dd></div><div><dt>隐私</dt><dd>分享版已脱敏</dd></div></dl><p className="privacy-note">{report.privacy_note}</p></section>
      </div>
      <section className="panel preview-panel"><div className="panel-heading"><div><div className="eyebrow small">SHARE REPORT</div><h2>报告预览</h2></div><div className="preview-actions"><button className="secondary-button" onClick={onCopy} disabled={!selectedId}>复制报告</button><button className="secondary-button" onClick={onExport} disabled={!selectedId}>另存为文件 ↗</button></div></div><div className="format-tabs" role="tablist" aria-label="报告格式">{(['json', 'html', 'issue'] as Format[]).map(item => <button key={item} role="tab" aria-selected={format === item} className={format === item ? 'selected' : ''} onClick={() => onFormat(item)}>{formatText[item]}</button>)}</div>{format === 'html' && preview.startsWith('<!doctype') ? <iframe className="html-preview" title="脱敏 HTML 报告预览" sandbox="" srcDoc={preview} /> : <pre className="text-preview">{preview || '选择一条已保存记录以预览报告。'}</pre>}</section>
    </> : <section className="empty-results"><div className="empty-symbol">⌁</div><h2>证据会在这里汇集</h2><p>运行诊断后，可查看逐层结果、可能原因和三种脱敏报告。</p></section>}
  </>
}
