import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { ComparePanel } from './ComparePanel'
import { ObservationPanel, VariantsPanel } from './BatchPanels'
import { dateText, EvidencePanel } from './EvidencePanel'
import { HarPanel } from './HarPanel'
import type { Comparison, CompleteEvent, DesktopBridge, Format, HarAnalysis, HistoryListing, HistorySummary, ObservationComplete, ObservationSample, ProgressEvent, Report, Status, TCPData, VariantResult, VariantsComplete } from './types'

type DiagnosisMode = 'single' | 'observation' | 'variants'

function bridge() { return window.go?.main?.App }
function message(error: unknown) { return error instanceof Error ? error.message : String(error) }
function bytesText(value: number) { return value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} KB` : `${(value / 1024 / 1024).toFixed(2)} MB` }
async function historyRecordExists(api: DesktopBridge, id: string) {
  try { await api.LoadReport(id); return true }
  catch { return false }
}

export function App() {
  const [available, setAvailable] = useState(Boolean(bridge()))
  const [input, setInput] = useState('')
  const [timeout, setTimeoutSeconds] = useState(20)
  const [mode, setMode] = useState<DiagnosisMode>('single')
  const [interval, setIntervalSeconds] = useState(10)
  const [duration, setDurationMinutes] = useState(5)
  const [samples, setSamples] = useState<ObservationSample[]>([])
  const [observationComplete, setObservationComplete] = useState<ObservationComplete | null>(null)
  const [variantRows, setVariantRows] = useState<VariantResult[]>([])
  const [variantsComplete, setVariantsComplete] = useState<VariantsComplete | null>(null)
  const [harAnalysis, setHarAnalysis] = useState<HarAnalysis | null>(null)
  const [harImporting, setHarImporting] = useState(false)
  const [harDiagnosticId, setHarDiagnosticId] = useState('')
  const [harDiagnostic, setHarDiagnostic] = useState<Report | null>(null)
  const [harDiagnosticLoading, setHarDiagnosticLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [canceling, setCanceling] = useState(false)
  const [progress, setProgress] = useState<Record<string, { status: Status; duration_ms: number }>>({})
  const [report, setReport] = useState<Report | null>(null)
  const [localTCP, setLocalTCP] = useState<TCPData | null>(null)
  const [selectedId, setSelectedId] = useState('')
  const [history, setHistory] = useState<HistoryListing>({ items: [], invalid_files: 0, total_files: 0, total_bytes: 0 })
  const [activeSummary, setActiveSummary] = useState<HistorySummary | null>(null)
  const [historyLoading, setHistoryLoading] = useState(false)
  const [retentionDays, setRetentionDays] = useState(90)
  const [view, setView] = useState<'diagnosis' | 'compare' | 'har'>('diagnosis')
  const [format, setFormat] = useState<Format>('json')
  const [preview, setPreview] = useState('')
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const [leftID, setLeftID] = useState('')
  const [rightID, setRightID] = useState('')
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')
  const runID = useRef('')
  const modeRef = useRef<DiagnosisMode>('single')
  const lastCompletedID = useRef('')
  const loadSequence = useRef(0)
  const historySequence = useRef(0)
  const harDiagnosticSequence = useRef(0)

  const refreshHistory = useCallback(async () => {
    const api = bridge()
    if (!api) return
    const sequence = ++historySequence.current
    setHistoryLoading(false)
    try {
      const listing = await api.ListHistory()
      if (sequence === historySequence.current) setHistory(listing)
    } catch (err) { if (sequence === historySequence.current) setError(`读取历史失败：${message(err)}`) }
  }, [])

  async function loadMoreHistory() {
    const api = bridge()
    const cursor = history.next_cursor
    if (!api || !cursor || historyLoading) return
    const sequence = historySequence.current
    setHistoryLoading(true)
    try {
      const page = await api.ListHistoryPage(cursor)
      if (sequence !== historySequence.current) return
      setHistory(current => ({
        ...page,
        items: [...current.items, ...page.items.filter(item => !current.items.some(existing => existing.id === item.id))],
        invalid_files: current.invalid_files + page.invalid_files,
      }))
    } catch (err) { if (sequence === historySequence.current) setError(`加载更多历史失败：${message(err)}`) }
    finally { if (sequence === historySequence.current) setHistoryLoading(false) }
  }

  useEffect(() => {
    const api = bridge()
    const events = window.runtime
    setAvailable(Boolean(api && events))
    if (!api || !events) return
    void refreshHistory()
    const offProgress = events.EventsOn('diagnostic:progress', payload => {
      if (modeRef.current !== 'single') return
      const event = payload as ProgressEvent
      if (runID.current && event.run_id !== runID.current) return
      setProgress(current => ({ ...current, [event.step.id]: event.step }))
    })
    const offComplete = events.EventsOn('diagnostic:complete', payload => {
      if (modeRef.current !== 'single') return
      const event = payload as CompleteEvent
      if (runID.current && event.run_id !== runID.current) return
      lastCompletedID.current = event.run_id
      runID.current = ''
      setBusy(false)
      setCanceling(false)
      if (event.error) setError(`诊断失败：${event.error}`)
      if (event.report) setReport(event.report)
      setLocalTCP(event.tcp ?? null)
      if (event.summary) { setSelectedId(event.summary.id); setActiveSummary(event.summary) }
      if (event.history_error) setError(`诊断完成，但保存历史失败：${event.history_error}`)
      if (event.cancelled) setNotice('诊断已取消；已完成的证据仍保留。')
      else if (!event.error) setNotice('诊断完成，脱敏报告已生成。')
      void refreshHistory()
    })
    const offObservationSample = events.EventsOn('observation:sample', payload => {
      if (modeRef.current !== 'observation') return
      const event = payload as ObservationSample
      if (runID.current && event.run_id !== runID.current) return
      setSamples(current => [...current, event])
    })
    const offObservationComplete = events.EventsOn('observation:complete', payload => {
      if (modeRef.current !== 'observation') return
      const event = payload as ObservationComplete
      if (runID.current && event.run_id !== runID.current) return
      lastCompletedID.current = event.run_id
      runID.current = ''
      setBusy(false); setCanceling(false); setObservationComplete(event)
      if (event.error) setError(event.error)
      else setNotice(event.cancelled ? '连续采样已取消；已有样本仍保留。' : `连续采样完成：${event.samples} 次，其中 ${event.failures} 次异常。`)
      void refreshHistory()
    })
    const offVariantResult = events.EventsOn('variants:result', payload => {
      if (modeRef.current !== 'variants') return
      const event = payload as VariantResult
      if (runID.current && event.run_id !== runID.current) return
      setVariantRows(current => [...current.filter(row => row.url !== event.url), event])
    })
    const offVariantsComplete = events.EventsOn('variants:complete', payload => {
      if (modeRef.current !== 'variants') return
      const event = payload as VariantsComplete
      if (runID.current && event.run_id !== runID.current) return
      lastCompletedID.current = event.run_id
      runID.current = ''
      setBusy(false); setCanceling(false); setVariantsComplete(event)
      setNotice(event.cancelled ? '网址入口对比已取消。' : '四种网址入口对比已完成。')
    })
    return () => { offProgress(); offComplete(); offObservationSample(); offObservationComplete(); offVariantResult(); offVariantsComplete() }
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
    setError(''); setNotice(''); setReport(null); setLocalTCP(null); setSelectedId(''); setActiveSummary(null); setProgress({}); setBusy(true); setCanceling(false); setView('diagnosis')
    setSamples([]); setObservationComplete(null); setVariantRows([]); setVariantsComplete(null)
    modeRef.current = mode
    runID.current = ''
    lastCompletedID.current = ''
    try {
      const id = mode === 'observation' ? await api.StartObservation(input.trim(), timeout, interval, duration)
        : mode === 'variants' ? await api.StartVariants(input.trim(), timeout)
          : await api.StartDiagnosis(input.trim(), timeout)
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
    if (!api || busy) return
    const sequence = ++loadSequence.current
    setError(''); setNotice(''); setView('diagnosis')
    setMode('single'); modeRef.current = 'single'
    try {
      const [loaded, tcp] = await Promise.all([api.LoadReport(item.id), api.LocalTCP(item.id)])
      if (sequence !== loadSequence.current) return
      setReport(loaded)
      setLocalTCP(tcp)
      setSelectedId(item.id)
      setActiveSummary(item)
    } catch (err) { if (sequence === loadSequence.current) setError(`打开历史失败：${message(err)}`) }
  }

  async function compare() {
    const api = bridge()
    if (!api || !leftID || !rightID || leftID === rightID) return
    setError('')
    try { setComparison(await api.CompareHistory(leftID, rightID)) }
    catch (err) { setError(`对比失败：${message(err)}`) }
  }

  async function importHar() {
    const api = bridge()
    if (!api || harImporting || busy) return
    setError(''); setNotice(''); setHarImporting(true)
    try {
      const analysis = await api.ImportHAR()
      if (analysis) {
        setHarAnalysis(analysis)
        setNotice(`已分析 ${analysis.supported_entries} 条浏览器 HTTP(S) 请求；原始 HAR 未写入历史。`)
      }
    } catch (err) { setError(`HAR 分析失败：${message(err)}`) }
    finally { setHarImporting(false) }
  }

  async function selectHarDiagnostic(id: string) {
    const api = bridge()
    const sequence = ++harDiagnosticSequence.current
    setHarDiagnosticId(id); setHarDiagnostic(null); setHarDiagnosticLoading(Boolean(id))
    if (!api || !id) return
    try {
      const report = await api.LoadReport(id)
      if (sequence === harDiagnosticSequence.current) setHarDiagnostic(report)
    } catch (err) { if (sequence === harDiagnosticSequence.current) setError(`读取对照诊断失败：${message(err)}`) }
    finally { if (sequence === harDiagnosticSequence.current) setHarDiagnosticLoading(false) }
  }

  async function exportReport() {
    const api = bridge()
    if (!api || !selectedId) return
    setError('')
    try {
      const path = await api.ExportReport(selectedId, format)
      if (path) setNotice(`报告已保存：${path}`)
    } catch (err) { setError(`保存失败：${message(err)}`) }
  }

  async function copyReport() {
    const api = bridge()
    const clipboard = window.runtime?.ClipboardSetText
    if (!api || !clipboard || !selectedId) return
    setError('')
    try {
      const content = await api.PreviewReport(selectedId, format)
      if (!await clipboard(content)) throw new Error('剪贴板未接受报告内容')
      setNotice('当前格式的脱敏报告已复制到剪贴板。')
    } catch (err) { setError(`复制失败：${message(err)}`) }
  }

  function reconcileHistory(listing: HistoryListing, removedID?: string) {
    ++historySequence.current
    setHistoryLoading(false)
    setHistory(listing)
    if (removedID && selectedId === removedID) {
      ++loadSequence.current
      setSelectedId(''); setActiveSummary(null); setReport(null); setLocalTCP(null); setPreview('')
    }
    if (removedID && (leftID === removedID || rightID === removedID)) {
      setLeftID(''); setRightID(''); setComparison(null)
    }
    if (removedID && harDiagnosticId === removedID) {
      ++harDiagnosticSequence.current
      setHarDiagnosticId(''); setHarDiagnostic(null); setHarDiagnosticLoading(false)
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
      reconcileHistory(listing)
      if (selectedId && !listing.items.some(item => item.id === selectedId) && !await historyRecordExists(api, selectedId)) {
        ++loadSequence.current
        setSelectedId(''); setActiveSummary(null); setReport(null); setLocalTCP(null); setPreview('')
      }
      if ((leftID && !listing.items.some(item => item.id === leftID) && !await historyRecordExists(api, leftID)) ||
        (rightID && !listing.items.some(item => item.id === rightID) && !await historyRecordExists(api, rightID))) {
        setLeftID(''); setRightID(''); setComparison(null)
      }
      if (harDiagnosticId && !listing.items.some(item => item.id === harDiagnosticId) && !await historyRecordExists(api, harDiagnosticId)) {
        ++harDiagnosticSequence.current
        setHarDiagnosticId(''); setHarDiagnostic(null); setHarDiagnosticLoading(false)
      }
      setNotice(`已清理 ${removed} 条过期诊断记录。`)
    } catch (err) { setError(`清理历史失败：${message(err)}`) }
  }

  const selectedSummary = history.items.find(item => item.id === selectedId) ?? (activeSummary?.id === selectedId ? activeSummary : undefined)
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">N<span>·</span></div><div><strong>NetEvidence</strong><small>网络故障证据工作台</small></div></div>
      <div className="sidebar-group-label">工作区</div>
      <button className={`nav-item ${view === 'diagnosis' ? 'active' : ''}`} onClick={() => setView('diagnosis')}><span className="nav-icon">⌁</span> 新建诊断</button>
      <button className={`nav-item ${view === 'compare' ? 'active' : ''}`} onClick={() => setView('compare')}><span className="nav-icon">⇄</span> 对比诊断</button>
      <button className={`nav-item ${view === 'har' ? 'active' : ''}`} onClick={() => setView('har')}><span className="nav-icon">▦</span> 浏览器记录</button>
      <div className="history-heading"><span>最近诊断</span><button onClick={() => void refreshHistory()} aria-label="刷新历史">↻</button></div>
      <div className="history-list">
        {history.items.length === 0 && <div className="empty-history">{history.total_files ? '本页没有可读取的诊断记录。' : '还没有本机诊断记录。'}</div>}
        {history.items.map(item => <button key={item.id} disabled={busy} className={`history-item ${selectedId === item.id && view === 'diagnosis' ? 'selected' : ''}`} onClick={() => void selectHistory(item)}>
          <span className={`outcome-dot ${item.outcome}`} /><span className="history-copy"><strong title={item.target}>{item.target}</strong><small>{dateText(item.saved_at)}</small></span>
        </button>)}
        {history.next_cursor && <button className="history-load-more" disabled={historyLoading} onClick={() => void loadMoreHistory()}>{historyLoading ? '加载中…' : '加载更多历史'}</button>}
      </div>
      <div className="history-management"><div>已载入 {history.items.length} / {history.total_files} 份文件 · {bytesText(history.total_bytes)}</div><div className="history-controls"><button disabled={!selectedId || busy} onClick={() => void deleteSelected()}>删除当前</button><select aria-label="保留期限" value={retentionDays} onChange={event => setRetentionDays(Number(event.target.value))}><option value={30}>保留 30 天</option><option value={90}>保留 90 天</option><option value={180}>保留 180 天</option></select><button disabled={!history.total_files || busy} onClick={() => void pruneHistory()}>清理旧记录</button></div></div>
      <div className="sidebar-foot"><span className="privacy-icon">◈</span><div>本机处理，分享前脱敏<small>历史仅保存在这台电脑</small></div></div>
    </aside>
    <main className="workspace">
      <header className="topbar"><span>诊断工作台 <span className="breadcrumb">/ {view === 'compare' ? '结果对比' : view === 'har' ? '浏览器记录' : '网络诊断'}</span></span><span className="local-badge"><i /> LOCAL DESKTOP</span></header>
      <div className="workspace-content">
        {!available && <div className="alert warning" role="status">桌面服务未连接。请使用 NetEvidence 桌面程序运行诊断。</div>}
        {error && <div className="alert error" role="alert">{error}<button onClick={() => setError('')} aria-label="关闭错误">×</button></div>}
        {notice && <div className="alert success" role="status">{notice}<button onClick={() => setNotice('')} aria-label="关闭提示">×</button></div>}
        {history.invalid_files > 0 && <div className="alert warning">已加载的历史中有 {history.invalid_files} 份文件无法读取，已跳过。</div>}
        {view === 'diagnosis' ? <>
          <div className="page-intro"><div className="eyebrow"><span className="eyebrow-line" /> NETWORK DIAGNOSTICS</div><h1>找到故障发生的那一层。</h1><p>输入目标地址，逐层查看 DNS、连接、证书与服务响应。结论会标明依据，分享时自动隐藏敏感信息。</p></div>
          <div className="diagnosis-mode" role="group" aria-label="诊断方式">{([
            ['single', '单次诊断'], ['observation', '连续采样'], ['variants', '网址入口对比'],
          ] as const).map(([value, label]) => <button key={value} type="button" className={mode === value ? 'selected' : ''} disabled={busy} onClick={() => { setMode(value); modeRef.current = value }}>{label}</button>)}</div>
          <form className="target-card" onSubmit={start}>
            <label htmlFor="target">诊断目标</label>
            <div className="target-row"><span className="input-icon">◎</span><input id="target" value={input} onChange={event => setInput(event.target.value)} placeholder="例如 example.com、https://example.com 或 host:port" autoComplete="off" spellCheck={false} disabled={busy || !available} /><button className="primary-button" type="submit" disabled={!available || busy || !input.trim()}>{busy ? '检查中…' : mode === 'observation' ? '开始采样' : mode === 'variants' ? '比较四种入口' : '开始诊断'} <span>→</span></button></div>
            <div className="target-options"><span>{mode === 'single' ? '总超时' : '单次超时'}</span><select value={timeout} onChange={event => setTimeoutSeconds(Number(event.target.value))} disabled={busy}><option value={10}>10 秒</option><option value={20}>20 秒</option><option value={30}>30 秒</option><option value={60}>60 秒</option></select>{mode === 'observation' && <><span>间隔</span><select aria-label="采样间隔" value={interval} onChange={event => setIntervalSeconds(Number(event.target.value))} disabled={busy}><option value={10}>10 秒</option><option value={30}>30 秒</option><option value={60}>60 秒</option></select><span>时长</span><select aria-label="采样时长" value={duration} onChange={event => setDurationMinutes(Number(event.target.value))} disabled={busy}><option value={5}>5 分钟</option><option value={10}>10 分钟</option><option value={30}>30 分钟</option></select></>}{mode === 'single' && <span className="option-note">整次上限；DNS/TCP 单层 3 秒，TLS/代理访问单层 5 秒。并行比较直连和系统手动代理。</span>}{mode === 'observation' && <span className="option-note">每次采样不会重叠；关闭窗口或点击取消会停止。</span>}{mode === 'variants' && <span className="option-note">仅支持主域名或 www，标准 80/443 端口；四种入口并行检查。</span>}{busy && <button className="cancel-button" type="button" onClick={() => void cancel()} disabled={canceling}>{canceling ? '正在取消…' : '取消检查'}</button>}</div>
          </form>
          {mode === 'single' ? <EvidencePanel report={report} localTCP={localTCP} busy={busy} progress={progress} selectedSummary={selectedSummary} selectedId={selectedId} format={format} preview={preview} onFormat={setFormat} onExport={() => void exportReport()} onCopy={() => void copyReport()} />
            : mode === 'observation' ? <ObservationPanel samples={samples} complete={observationComplete} busy={busy} onOpen={item => void selectHistory(item)} />
              : <VariantsPanel rows={variantRows} complete={variantsComplete} busy={busy} />}
        </> : view === 'compare' ? <ComparePanel history={history.items} leftID={leftID} rightID={rightID} comparison={comparison} onLeft={id => { setLeftID(id); setComparison(null) }} onRight={id => { setRightID(id); setComparison(null) }} onCompare={() => void compare()} />
          : <HarPanel analysis={harAnalysis} importing={harImporting || busy} onImport={() => void importHar()} history={history.items} diagnosticId={harDiagnosticId} onDiagnostic={id => void selectHarDiagnostic(id)} diagnostic={harDiagnostic} diagnosticLoading={harDiagnosticLoading} />}
      </div>
    </main>
  </div>
}
