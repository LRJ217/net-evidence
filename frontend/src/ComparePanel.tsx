import { dateText, layers, statusText } from './EvidencePanel'
import type { Comparison, HistorySummary } from './types'

interface Props {
  history: HistorySummary[]
  leftID: string
  rightID: string
  comparison: Comparison | null
  onLeft: (id: string) => void
  onRight: (id: string) => void
  onCompare: () => void
}

export function ComparePanel({ history, leftID, rightID, comparison, onLeft, onRight, onCompare }: Props) {
  return <>
    <div className="page-intro compare-intro"><div className="eyebrow"><span className="eyebrow-line" /> CHANGE OVER TIME</div><h1>比较两次诊断。</h1><p>选择两条本机记录，查看每一层的状态变化和耗时差异。</p></div>
    <section className="panel compare-picker"><div className="compare-select"><label htmlFor="left-run">较早记录</label><select id="left-run" value={leftID} onChange={event => onLeft(event.target.value)}><option value="">选择诊断</option>{history.map(item => <option value={item.id} key={item.id}>{dateText(item.saved_at)} · {item.target}</option>)}</select></div><span className="compare-arrow">→</span><div className="compare-select"><label htmlFor="right-run">较新记录</label><select id="right-run" value={rightID} onChange={event => onRight(event.target.value)}><option value="">选择诊断</option>{history.map(item => <option value={item.id} key={item.id}>{dateText(item.saved_at)} · {item.target}</option>)}</select></div><button className="primary-button" disabled={!leftID || !rightID || leftID === rightID} onClick={onCompare}>开始对比</button></section>
    {comparison ? <section className="panel comparison-panel"><div className="panel-heading"><div><div className="eyebrow small">SIDE BY SIDE</div><h2>变化明细</h2></div><span className="section-meta">右侧减左侧</span></div><div className="compare-targets"><div><small>较早记录</small><strong>{comparison.left.target}</strong><span>{dateText(comparison.left.saved_at)}</span></div><div><small>较新记录</small><strong>{comparison.right.target}</strong><span>{dateText(comparison.right.saved_at)}</span></div></div><div className="table-scroll"><table><thead><tr><th>探测层</th><th>较早状态</th><th>较新状态</th><th>较早耗时</th><th>较新耗时</th><th>变化</th></tr></thead><tbody>{comparison.rows.map(row => <tr key={row.id}><td>{layers.find(layer => layer.id === row.id)?.label ?? row.id}</td><td><span className={`table-status ${row.left_status}`}>{statusText[row.left_status]}</span></td><td><span className={`table-status ${row.right_status}`}>{statusText[row.right_status]}</span></td><td>{row.left_duration_ms} ms</td><td>{row.right_duration_ms} ms</td><td className={row.changed ? 'changed' : ''}>{row.delta_ms > 0 ? '+' : ''}{row.delta_ms} ms{row.changed && ' · 状态变化'}</td></tr>)}</tbody></table></div><p className="comparison-note">HTTP 状态码：{comparison.left_http_status || '—'} → {comparison.right_http_status || '—'}。不同时间的网络状态可能变化；对比仅描述观测差异。</p></section> : <section className="empty-results"><div className="empty-symbol">⇄</div><h2>选择两次诊断</h2><p>对比会显示 DNS、TCP、TLS、HTTP 和本机环境的状态与耗时变化。</p></section>}
  </>
}
