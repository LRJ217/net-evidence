import { dateText, statusText } from './EvidencePanel'
import type { HistorySummary, ObservationComplete, ObservationSample, VariantResult, VariantsComplete } from './types'

const outcomeText: Record<string, string> = {
  success: '可访问', failure: '失败', attention: 'HTTP 异常', partial: '未完成',
  proxy_accessible: '仅代理可访问', proxy_failure: '直连可访问，代理异常',
}

interface ObservationProps {
  samples: ObservationSample[]
  complete: ObservationComplete | null
  busy: boolean
  onOpen: (summary: HistorySummary) => void
}

export function ObservationPanel({ samples, complete, busy, onOpen }: ObservationProps) {
  const successes = samples.filter(sample => sample.outcome === 'success').length
  const failures = samples.length - successes
  const firstFailure = samples.find(sample => sample.outcome !== 'success')
  return <section className="panel batch-panel">
    <div className="panel-heading"><div><div className="eyebrow small">INTERMITTENT CHECK</div><h2>连续采样</h2></div><span className="section-meta">{busy ? '采样中…' : complete ? '已结束' : '等待开始'}</span></div>
    <p className="batch-note">按设定间隔依次探测；“成功”表示直连与已配置的代理探测均正常。只保存异常样本和首个成功样本。如需查看样本详情，请先结束采样。页面关闭后，本次汇总不保留，已保存的样本仍可在历史中查看。</p>
    <div className="batch-stats"><div><strong>{samples.length}</strong><small>总样本</small></div><div><strong>{successes}</strong><small>成功</small></div><div><strong>{failures}</strong><small>异常或未完成</small></div><div><strong>{samples.length ? `${Math.round(successes / samples.length * 100)}%` : '—'}</strong><small>成功率</small></div></div>
    {firstFailure && <p className="batch-highlight">首次异常：{dateText(firstFailure.started_at)} · {firstFailure.failure_layer || outcomeText[firstFailure.outcome] || firstFailure.outcome}</p>}
    {complete?.history_errors ? <p className="batch-highlight">{complete.history_errors} 份样本保存失败，请检查本机历史目录。</p> : null}
    {complete?.error ? <p className="batch-highlight">{complete.error}</p> : null}
    {samples.length ? <div className="table-scroll batch-table"><table><thead><tr><th>序号</th><th>时间</th><th>结果</th><th>故障层</th><th>耗时</th><th>历史</th></tr></thead><tbody>{samples.map(sample => <tr key={sample.number}><td>{sample.number}</td><td>{dateText(sample.started_at)}</td><td>{outcomeText[sample.outcome] ?? sample.outcome}</td><td>{sample.failure_layer || '—'}</td><td>{sample.duration_ms} ms</td><td>{sample.saved ? <button className="inline-link" disabled={busy} onClick={() => onOpen(sample.saved!)}>查看</button> : sample.history_error ? '保存失败' : '未保存'}</td></tr>)}</tbody></table></div> : <div className="empty-batch">开始后会逐次显示采样结果。</div>}
  </section>
}

interface VariantsProps {
  rows: VariantResult[]
  complete: VariantsComplete | null
  busy: boolean
}

export function VariantsPanel({ rows, complete, busy }: VariantsProps) {
  const ordered = [...rows].sort((a, b) => a.url.localeCompare(b.url))
  return <section className="panel batch-panel">
    <div className="panel-heading"><div><div className="eyebrow small">ENTRY COMPARISON</div><h2>四种网址入口</h2></div><span className="section-meta">{rows.length} / 4 {busy ? '检查中…' : complete ? '已完成' : '等待开始'}</span></div>
    <p className="batch-note">比较主域名与 www 的 HTTP、HTTPS 首页；输入中的路径与查询不会被请求。HTTP 入口的 TLS“跳过”只表示没有对初始入口单独探测 TLS，HTTP 请求仍可跳转至 HTTPS。结果仅在当前窗口显示，不写入诊断历史。</p>
    {rows.length ? <div className="table-scroll batch-table"><table><thead><tr><th>入口</th><th>结果</th><th>DNS</th><th>TCP</th><th>TLS</th><th>HTTP</th><th>状态码</th><th>最终地址</th><th>耗时</th></tr></thead><tbody>{ordered.map(row => <tr key={row.url}><td>{row.url}</td><td>{outcomeText[row.outcome] ?? row.outcome}</td><td>{statusText[row.dns]}</td><td>{statusText[row.tcp]}</td><td>{statusText[row.tls]}</td><td>{statusText[row.http]}</td><td>{row.http_code || '—'}</td><td title={row.final_url}>{row.final_url || '—'}</td><td>{row.duration_ms} ms</td></tr>)}</tbody></table></div> : <div className="empty-batch">开始后会显示四种入口的结果。</div>}
    {complete?.cancelled && <p className="batch-highlight">入口对比已取消；已完成的结果仍保留。</p>}
  </section>
}
