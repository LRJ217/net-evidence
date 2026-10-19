export type Status = 'success' | 'failure' | 'partial' | 'skipped'
export type Format = 'json' | 'html' | 'issue'

export interface ProbeError { kind: string; message: string }
export interface TCPAttempt { family: string; address: string; status: Status; duration_ms: number; error?: ProbeError }
export interface TCPData { connected_address?: string; attempts?: TCPAttempt[] }
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
  dns: Step<{ ipv4: string[]; ipv6: string[]; address_kinds?: { private?: number; loopback?: number; link_local?: number; other?: number } }>
  tcp: Step<TCPData>
  tls: Step<{ protocol: string; cipher_suite: string; hostname_valid: boolean; time_valid: boolean; verified: boolean }>
  http: Step<{ status_code: number; final_url: string; hops: { url: string; status_code: number; duration_ms: number }[] }>
  proxy_http?: Step<{ status_code: number; final_url: string; transport: string; hops: { url: string; status_code: number; duration_ms: number }[] }>
  environment: Step<{ proxy: { enabled: boolean; env_present: boolean; bypass_list?: string; auto_config_url?: string }; interfaces: { name: string; addresses: string[]; mac?: string }[] }>
}

export interface Finding { id: string; title: string; explanation: string; evidence_ids: string[] }
export interface Report { schema_version: number; privacy_note: string; evidence: Evidence; findings: Finding[] }
export interface HistorySummary { id: string; saved_at: string; target: string; outcome: string; duration_ms: number }
export interface HistoryListing { items: HistorySummary[]; invalid_files: number; total_files: number; total_bytes: number; next_cursor?: string }
export interface ProgressEvent { run_id: string; step: { id: string; status: Status; duration_ms: number } }
export interface CompleteEvent {
  run_id: string
  summary?: HistorySummary
  report?: Report
  tcp?: TCPData
  cancelled: boolean
  history_error?: string
  error?: string
}
export interface ObservationSample {
  run_id: string
  number: number
  started_at: string
  outcome: string
  failure_layer?: string
  duration_ms: number
  saved?: HistorySummary
  history_error?: boolean
}
export interface ObservationComplete {
  run_id: string
  samples: number
  successes: number
  failures: number
  history_errors: number
  cancelled: boolean
  error?: string
}
export interface VariantResult {
  run_id: string
  url: string
  outcome: string
  dns: Status
  tcp: Status
  tls: Status
  http: Status
  http_code: number
  final_url?: string
  failure_layer?: string
  duration_ms: number
}
export interface VariantsComplete { run_id: string; cancelled: boolean }
export interface HarResource {
  number: number
  url: string
  host: string
  method: string
  kind: string
  issue: string
  status: number
  duration_ms: number
  offset_ms?: number
  dns_ms?: number
  connect_ms?: number
  tls_ms?: number
  wait_ms?: number
  receive_ms?: number
}
export interface HarHostSummary { host: string; requests: number; problems: number; slow: number }
export interface HarAnalysis {
  schema_version: number
  capture_started_at?: string
  main_host?: string
  total_entries: number
  supported_entries: number
  ignored_entries: number
  no_response: number
  http_errors: number
  slow: number
  document_ok: boolean
  other_host_requests: number
  rows: HarResource[]
  omitted_rows: number
  hosts: HarHostSummary[]
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
  environment: {
    available: boolean
    proxy_enabled_changed: boolean
    proxy_server_changed: boolean
    proxy_bypass_changed: boolean
    pac_changed: boolean
    env_proxy_presence_changed: boolean
    network_interfaces_changed: boolean
    dns_answers_available: boolean
    dns_answers_changed: boolean
  }
}

export interface DesktopBridge {
  StartDiagnosis(input: string, timeoutSeconds: number): Promise<string>
  StartObservation(input: string, timeoutSeconds: number, intervalSeconds: number, durationMinutes: number): Promise<string>
  StartVariants(input: string, timeoutSeconds: number): Promise<string>
  ImportHAR(): Promise<HarAnalysis | null>
  CancelDiagnosis(): Promise<boolean>
  ListHistory(): Promise<HistoryListing>
  ListHistoryPage(afterID: string): Promise<HistoryListing>
  DeleteHistory(id: string): Promise<void>
  PruneHistory(days: number): Promise<number>
  LocalTCP(id: string): Promise<TCPData | null>
  LoadReport(id: string): Promise<Report>
  PreviewReport(id: string, format: Format): Promise<string>
  CompareHistory(leftID: string, rightID: string): Promise<Comparison>
  ExportReport(id: string, format: Format): Promise<string>
}

declare global {
  interface Window {
    go?: { main?: { App?: DesktopBridge } }
    runtime?: { EventsOn: (name: string, callback: (payload: unknown) => void) => () => void; ClipboardSetText: (text: string) => Promise<boolean> }
  }
}
