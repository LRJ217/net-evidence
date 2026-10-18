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

function environmentChanges(comparison: Comparison): string[] {
  const diff = comparison.environment
  return [
    diff.proxy_enabled_changed && '系统代理启用状态改变',
    diff.proxy_server_changed && '手动代理地址改变',
    diff.proxy_bypass_changed && '代理绕过规则改变',
    diff.pac_changed && 'PAC 配置改变',
    diff.env_proxy_presence_changed && '环境变量代理配置状态改变',
    diff.network_interfaces_changed && '网卡或其地址改变（可能与 VPN 切换有关）',
    diff.dns_answers_changed && 'DNS 解析结果改变（不能据此断定 DNS 配置改变）',
  ].filter((item): item is string => Boolean(item))
}

export function ComparePanel({ history, leftID, rightID, comparison, onLeft, onRight, onCompare }: Props) {
  const changes = comparison ? environmentChanges(comparison) : []
  return <>
    <div className="page-intro compare-intro"><div className="eyebrow"><span className="eyebrow-line" /> CHANGE OVER TIME</div><h1>比较两次诊断。</h1><p>选择两条本机记录，查看逐层状态、耗时和网络环境变化。</p></div>
    <section className="panel compare-picker">
      <div className="compare-select"><label htmlFor="left-run">较早记录</label><select id="left-run" value={leftID} onChange={event => onLeft(event.target.value)}><option value="">选择诊断</option>{history.map(item => <option value={item.id} key={item.id}>{dateText(item.saved_at)} · {item.target}</option>)}</select></div>
      <span className="compare-arrow">→</span>
      <div className="compare-select"><label htmlFor="right-run">较新记录</label><select id="right-run" value={rightID} onChange={event => onRight(event.target.value)}><option value="">选择诊断</option>{history.map(item => <option value={item.id} key={item.id}>{dateText(item.saved_at)} · {item.target}</option>)}</select></div>
      <button className="primary-button" disabled={!leftID || !rightID || leftID === rightID} onClick={onCompare}>开始对比</button>
    </section>
    {comparison ? <section className="panel comparison-panel">
      <div className="panel-heading"><div><div className="eyebrow small">SIDE BY SIDE</div><h2>变化明细</h2></div><span className="section-meta">右侧减左侧</span></div>
      <div className="compare-targets"><div><small>较早记录</small><strong>{comparison.left.target}</strong><span>{dateText(comparison.left.saved_at)}</span></div><div><small>较新记录</small><strong>{comparison.right.target}</strong><span>{dateText(comparison.right.saved_at)}</span></div></div>
      <div className="table-scroll"><table><thead><tr><th>探测层</th><th>较早状态</th><th>较新状态</th><th>较早耗时</th><th>较新耗时</th><th>变化</th></tr></thead><tbody>{comparison.rows.map(row => <tr key={row.id}><td>{layers.find(layer => layer.id === row.id)?.label ?? row.id}</td><td><span className={`table-status ${row.left_status}`}>{statusText[row.left_status]}</span></td><td><span className={`table-status ${row.right_status}`}>{statusText[row.right_status]}</span></td><td>{row.left_duration_ms} ms</td><td>{row.right_duration_ms} ms</td><td className={row.changed ? 'changed' : ''}>{row.delta_ms > 0 ? '+' : ''}{row.delta_ms} ms{row.changed && ' · 状态变化'}</td></tr>)}</tbody></table></div>
      <p className="comparison-note">HTTP 状态码：{comparison.left_http_status || '—'} → {comparison.right_http_status || '—'}。对比只描述观测差异，不证明根因。</p>
      <div className="environment-diff"><h3>网络环境变化</h3>{changes.length ? <ul>{changes.map(change => <li key={change}>{change}</li>)}</ul> : <p>{comparison.environment.available && comparison.environment.dns_answers_available ? '本次采集范围内未发现变化。' : '可比较的证据中未发现变化。'}</p>}{!comparison.environment.available && <p>至少一条记录缺少代理与网卡证据。</p>}{!comparison.environment.dns_answers_available && <p>DNS 答案仅在同一目标且两次都有地址证据时比较。</p>}<small>仅显示是否变化，不展示代理、网卡或 IP 的原始值。</small></div>
    </section> : <section className="empty-results"><div className="empty-symbol">⇄</div><h2>选择两次诊断</h2><p>对比会显示逐层结果和已采集的网络环境变化。</p></section>}
  </>
}
