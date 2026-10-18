import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { ComparePanel } from './ComparePanel'
import { dateText, EvidencePanel } from './EvidencePanel'
import type { Comparison, CompleteEvent, Format, HistoryListing, HistorySummary, ProgressEvent, Report, Status, TCPData } from './types'

function bridge() { return window.go?.main?.App }
function message(error: unknown) { return error instanceof Error ? error.message : String(error) }
function bytesText(value: number) { return value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1024 / 1024).toFixed(2)} MB` }

export function App() {
  const [available, setAvailable] = useState(Boolean(bridge()))
  const [input, setInput] = useState('')
  const [timeout, setTimeoutSeconds] = useState(20)
  const [busy, setBusy] = useState(false)
  const [canceling, setCanceling] = useState(false)
  const [progress, setProgress] = useState<Record<string, { status: Status; duration_ms: number }>>({})
  const [report, setReport] = useState<Report | null>(null)
  const [localTCP, setLocalTCP] = useState<TCPData | null>(null)
  const [selectedId, setSelectedId] = useState('')
  const [history, setHistory] = useState<HistoryListing>({ items: [], invalid_files: 0, total_files: 0, total_bytes: 0 })
  const [retentionDays, setRetentionDays] = useState(90)
  const [view, setView] = useState<'diagnosis' | 'compare'>('diagnosis')
  const [format, setFormat] = useState<Format>('json')
  const [preview, setPreview] = useState('')
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const [leftID, setLeftID] = useState('')
  const [rightID, setRightID] = useState('')
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const runID = useRef('')
  const lastCompletedID = useRef('')
  const loadSequence = useRef(0)

  const refreshHistory = useCallback(async () => {
    const api = bridge()
    if (!api) return
    try { setHistory(await api.ListHistory()) }
    catch (err) { setError(`读取历史失败：${message(err)}`) }
  }, [])

  useEffect(() => {
    const api = bridge()
    const events = window.runtime
    setAvailable(Boolean(api && events))
    if (!api || !events) return
    void refreshHistory()
    const offProgress = events.EventsOn('diagnostic:progress', payload => {
      const event = payload as ProgressEvent
      if (runID.current && event.run_id !== runID.current) return
      setProgress(current => ({ ...current, [event.step.id]: event.step }))
    })
    const offComplete = events.EventsOn('diagnostic:complete', payload => {
      const event = payload as CompleteEvent
      if (runID.current && event.run_id !== runID.current) return
      lastCompletedID.current = event.run_id
      runID.current = ''
      setBusy(false)
      setCanceling(false)
      if (event.error) setError(`诊断失败：${event.error}`)
      if (event.report) setReport(event.report)
      setLocalTCP(event.tcp ?? null)
      if (event.summary) setSelectedId(event.summary.id)
      if (event.history_error) setError(`诊断完成，但保存历史失败：${event.history_error}`)
      if (event.cancelled) setNotice('诊断已取消；已完成的证据仍保留。')
      else if (!event.error) setNotice('诊断完成，脱敏报告已生成。')
      void refreshHistory()
    })
    return () => { offProgress(); offComplete() }
  }, [refreshHistory])

  useEffect(() => {
    const api = bridge()
    if (!api || !selectedId) { setPreview(''); return }
    let disposed = false
    setPreview('正在生成预览…')
    api.PreviewReport(selectedId, format).then(value => {
      if (!disposed) setPreview(value)
    }).catch(err => { if (!disposed) setError(`报告预览失败：${message(err)}`) })
    return () => { disposed = true }
  }, [selectedId, format])

  async function start(event: FormEvent) {
    event.preventDefault()
    const api = bridge()
    if (!api || !input.trim() || busy) return
    setError(''); setNotice(''); setReport(null); setLocalTCP(null); setSelectedId(''); setProgress({}); setBusy(true); setCanceling(false); setView('diagnosis')
    runID.current = ''
    lastCompletedID.current = ''
    try {
      const id = await api.StartDiagnosis(input.trim(), timeout)
      if (lastCompletedID.current !== id) runID.current = id
    } catch (err) {
      setBusy(false)
      setError(`无法开始诊断：${message(err)}`)
    }
  }

  async function cancel() {
    const api = bridge()
    if (!api) return
    try { if (await api.CancelDiagnosis()) setCanceling(true) }
    catch (err) { setError(`取消失败：${message(err)}`) }
  }

  async function selectHistory(item: HistorySummary) {
    const api = bridge()
    if (!api) return
    const sequence = ++loadSequence.current
    setError(''); setNotice(''); setView('diagnosis')
    try {
      const [loaded, tcp] = await Promise.all([api.LoadReport(item.id), api.LocalTCP(item.id)])
      if (sequence !== loadSequence.current) return
      setReport(loaded)
      setLocalTCP(tcp)
      setSelectedId(item.id)
    } catch (err) { if (sequence === loadSequence.current) setError(`打开历史失败：${message(err)}`) }
  }

  async function compare() {
    const api = bridge()
    if (!api || !leftID || !rightID || leftID === rightID) return
    setError('')
    try { setComparison(await api.CompareHistory(leftID, rightID)) }
    catch (err) { setError(`对比失败：${message(err)}`) }
  }

  async function exportReport() {
    const api = bridge()
    if (!api || !selectedId) return
    setError('')
    try {
      const path = await api.ExportReport(selectedId, format)
      if (path) setNotice(`报告已保存：${path}`)
    } catch (err) { setError(`保存失败：${message(err)}。若文件已存在，请换一个文件名。`) }
  }

  function reconcileHistory(listing: HistoryListing, removedID?: string) {
    setHistory(listing)
    if (removedID && selectedId === removedID) {
      ++loadSequence.current
      setSelectedId(''); setReport(null); setLocalTCP(null); setPreview('')
    }
    if (removedID && (leftID === removedID || rightID === removedID)) {
      setLeftID(''); setRightID(''); setComparison(null)
    }
  }

  async function deleteSelected() {
    const api = bridge()
    if (!api || !selectedId || busy) return
    if (!window.confirm('删除当前诊断的本机原始记录？此操作无法撤销。')) return
    try {
      await api.DeleteHistory(selectedId)
      const listing = await api.ListHistory()
      reconcileHistory(listing, selectedId)
      setNotice('已删除当前诊断记录。')
    } catch (err) { setError(`删除历史失败：${message(err)}`) }
  }

  async function pruneHistory() {
    const api = bridge()
    if (!api || busy) return
    if (!window.confirm(`删除 ${retentionDays} 天前的本机诊断记录？此操作无法撤销。`)) return
    try {
      const removed = await api.PruneHistory(retentionDays)
      const listing = await api.ListHistory()
      setHistory(listing)
      if (selectedId && !listing.items.some(item => item.id === selectedId)) {
        ++loadSequence.current
        setSelectedId(''); setReport(null); setLocalTCP(null); setPreview('')
      }
      if ((leftID && !listing.items.some(item => item.id === leftID)) || (rightID && !listing.items.some(item => item.id === rightID))) {
        setLeftID(''); setRightID(''); setComparison(null)
      }
      setNotice(`已清理 ${removed} 条过期诊断记录。`)
    } catch (err) { setError(`清理历史失败：${message(err)}`) }
  }

  const selectedSummary = history.items.find(item => item.id === selectedId)
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">N<span>·</span></div><div><strong>NetEvidence</strong><small>网络故障证据工作台</small></div></div>
      <div className="sidebar-group-label">工作区</div>
      <button className={`nav-item ${view === 'diagnosis' ? 'active' : ''}`} onClick={() => setView('diagnosis')}><span className="nav-icon">⌁</span> 新建诊断</button>
      <button className={`nav-item ${view === 'compare' ? 'active' : ''}`} onClick={() => setView('compare')}><span className="nav-icon">⇄</span> 对比诊断</button>
      <div className="history-heading"><span>最近诊断</span><button onClick={() => void refreshHistory()} aria-label="刷新历史">↻</button></div>
      <div className="history-list">
        {history.items.length === 0 && <div className="empty-history">还没有本机诊断记录。</div>}
        {history.items.map(item => <button key={item.id} className={`history-item ${selectedId === item.id && view === 'diagnosis' ? 'selected' : ''}`} onClick={() => void selectHistory(item)}>
          <span className={`outcome-dot ${item.outcome}`} /><span className="history-copy"><strong title={item.target}>{item.target}</strong><small>{dateText(item.saved_at)}</small></span>
        </button>)}
      </div>
      <div className="history-management"><div>{history.total_files} 份记录 · {bytesText(history.total_bytes)}</div><div className="history-controls"><button disabled={!selectedId || busy} onClick={() => void deleteSelected()}>删除当前</button><select aria-label="保留期限" value={retentionDays} onChange={event => setRetentionDays(Number(event.target.value))}><option value={30}>保留 30 天</option><option value={90}>保留 90 天</option><option value={180}>保留 180 天</option></select><button disabled={!history.total_files || busy} onClick={() => void pruneHistory()}>清理旧记录</button></div></div>
      <div className="sidebar-foot"><span className="privacy-icon">◈</span><div>本机处理，分享前脱敏<small>历史仅保存在这台电脑</small></div></div>
    </aside>
    <main className="workspace">
      <header className="topbar"><span>诊断工作台 <span className="breadcrumb">/ {view === 'compare' ? '结果对比' : '网络诊断'}</span></span><span className="local-badge"><i /> LOCAL DESKTOP</span></header>
      <div className="workspace-content">
        {!available && <div className="alert warning" role="status">桌面服务未连接。请使用 NetEvidence 桌面程序运行诊断。</div>}
        {error && <div className="alert error" role="alert">{error}<button onClick={() => setError('')} aria-label="关闭错误">×</button></div>}
        {notice && <div className="alert success" role="status">{notice}<button onClick={() => setNotice('')} aria-label="关闭提示">×</button></div>}
        {history.invalid_files > 0 && <div className="alert warning">有 {history.invalid_files} 份历史文件无法读取，已跳过。</div>}
        {view === 'diagnosis' ? <>
          <div className="page-intro"><div className="eyebrow"><span className="eyebrow-line" /> NETWORK DIAGNOSTICS</div><h1>找到故障发生的那一层。</h1><p>输入目标地址，逐层查看 DNS、连接、证书与服务响应。结论会标明依据，分享时自动隐藏敏感信息。</p></div>
          <form className="target-card" onSubmit={start}>
            <label htmlFor="target">诊断目标</label>
            <div className="target-row"><span className="input-icon">◎</span><input id="target" value={input} onChange={event => setInput(event.target.value)} placeholder="例如 example.com、https://example.com 或 host:port" autoComplete="off" spellCheck={false} disabled={busy || !available} /><button className="primary-button" type="submit" disabled={!available || busy || !input.trim()}>{busy ? '诊断中…' : '开始诊断'} <span>→</span></button></div>
            <div className="target-options"><span>总超时</span><select value={timeout} onChange={event => setTimeoutSeconds(Number(event.target.value))} disabled={busy}><option value={10}>10 秒</option><option value={20}>20 秒</option><option value={30}>30 秒</option><option value={60}>60 秒</option></select><span className="option-note">整次上限；DNS/TCP 单层 3 秒，TLS/代理访问单层 5 秒。并行比较直连和系统手动代理。</span>{busy && <button className="cancel-button" type="button" onClick={() => void cancel()} disabled={canceling}>{canceling ? '正在取消…' : '取消诊断'}</button>}</div>
          </form>
          <EvidencePanel report={report} localTCP={localTCP} busy={busy} progress={progress} selectedSummary={selectedSummary} selectedId={selectedId} format={format} preview={preview} onFormat={setFormat} onExport={() => void exportReport()} />
        </> : <ComparePanel history={history.items} leftID={leftID} rightID={rightID} comparison={comparison} onLeft={id => { setLeftID(id); setComparison(null) }} onRight={id => { setRightID(id); setComparison(null) }} onCompare={() => void compare()} />}
      </div>
    </main>
  </div>
}
