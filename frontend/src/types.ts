export type Status = 'success' | 'failure' | 'partial' | 'skipped'
export type Format = 'json' | 'html' | 'issue'

export interface ProbeError { kind: string; message: string }
export interface Step<T = Record<string, unknown>> {
  id: string
  status: Status
  duration_ms: number
  data?: T
  error?: ProbeError
  reason?: string
}

export interface Evidence {
  schema_version: number
  tool_version: string
  started_at: string
  duration_ms: number
  target: { input: string; url: string; scheme: string; host: string; port: string; address: string }
  dns: Step<{ ipv4: string[]; ipv6: string[] }>
  tcp: Step<{ connected_address: string }>
  tls: Step<{ protocol: string; cipher_suite: string; hostname_valid: boolean; time_valid: boolean; verified: boolean }>
  http: Step<{ status_code: number; final_url: string; hops: { url: string; status_code: number; duration_ms: number }[] }>
  environment: Step<{ proxy: { enabled: boolean; env_present: boolean }; interfaces: { name: string; addresses: string[]; mac?: string }[] }>
}

export interface Finding { id: string; title: string; explanation: string; evidence_ids: string[] }
export interface Report { schema_version: number; privacy_note: string; evidence: Evidence; findings: Finding[] }
export interface HistorySummary { id: string; saved_at: string; target: string; outcome: string; duration_ms: number }
export interface HistoryListing { items: HistorySummary[]; invalid_files: number }
export interface ProgressEvent { run_id: string; step: { id: string; status: Status; duration_ms: number } }
export interface CompleteEvent {
  run_id: string
  summary?: HistorySummary
  report?: Report
  cancelled: boolean
  history_error?: string
  error?: string
}
export interface ComparisonRow {
  id: string
  left_status: Status
  right_status: Status
  left_duration_ms: number
  right_duration_ms: number
  delta_ms: number
  changed: boolean
}
export interface Comparison {
  left: HistorySummary
  right: HistorySummary
  rows: ComparisonRow[]
  left_http_status: number
  right_http_status: number
}

export interface DesktopBridge {
  StartDiagnosis(input: string, timeoutSeconds: number): Promise<string>
  CancelDiagnosis(): Promise<boolean>
  ListHistory(): Promise<HistoryListing>
  LoadReport(id: string): Promise<Report>
  PreviewReport(id: string, format: Format): Promise<string>
  CompareHistory(leftID: string, rightID: string): Promise<Comparison>
  ExportReport(id: string, format: Format): Promise<string>
}

declare global {
  interface Window {
    go?: { main?: { App?: DesktopBridge } }
    runtime?: { EventsOn: (name: string, callback: (payload: unknown) => void) => () => void }
  }
}
