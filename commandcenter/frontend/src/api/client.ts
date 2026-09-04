/** REST + WebSocket client for THE VOID Command Center. */
import { sessionHeaders } from './session'

import type {
  CoverageResponse,
  ComplianceResponse,
  DriftResponse,
  MitreResponse,
  ScenariosResponse,
} from '../types/insights'

const API_BASE = ''

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { Accept: 'application/json', ...(init?.headers || {}), ...sessionHeaders() },
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status} ${path}: ${text}`)
  }
  return res.json() as Promise<T>
}

async function download(path: string): Promise<Blob> {
  const res = await fetch(`${API_BASE}${path}`, { headers: { Accept: 'application/json', ...sessionHeaders() } })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status} ${path}: ${text}`)
  }
  return res.blob()
}

export type Status = {
  engaged: boolean
  demo_mode: boolean
  targets: string[]
  target_count: number
  active_sessions: string[]
  stolen_data: number
  stealth_active: boolean
  warlog_entries: number
  attack_log: number
  beacons: string[]
  beacon_count: number
  c2_status: Record<string, unknown>
  c2_channels: number
  c2_active_channels: number
  c2_recorded_channels: number
  c2_beacons: number
  c2_tasks: number
  boneyard_items: number
  degraded: string[]
}

export interface TargetHost {
  id?: string
  ip_address?: string
  hostname?: string
  domain?: string
  status?: string
  is_critical?: number | boolean
  first_seen?: string
  last_seen?: string
  created_at?: string
  epoch?: number
  [key: string]: unknown
}

export interface Finding {
  id?: string
  category?: string
  title?: string
  data?: Record<string, unknown>
  tags?: string[]
  risk_score?: number
  timestamp?: string
  epoch?: number
  host_id?: string
  [key: string]: unknown
}

export interface DemoStatus {
  demo_mode: boolean
  scenario: string | null
  hosts: number
  steps: number
  outcomes: number
  engagements: number
  note?: string
}

export interface LicenseStatus {
  state: string
  permitted: boolean
  required: boolean
  message: string
  customer_id: string | null
  license_id: string | null
  expires_at: string | null
  features: string[]
  product_version: string | null
}

export interface HealthResponse {
  ok: boolean
  service: 'the-void-command-center'
  host: string
  port: number
  degraded: string[]
  license: LicenseStatus
}

export interface WarLogEntry {
  id?: string
  timestamp?: string
  epoch?: number
  level?: string
  module?: string
  message?: string
  target?: string
  event_type?: string
  span_id?: string
  trace_id?: string
  data?: Record<string, unknown>
  [key: string]: unknown
}

export interface Channel {
  channel_id: string
  status: string
  source?: 'live' | 'evidence'
  live?: boolean
  last_known_status?: string
  endpoint?: string
  beacon_count?: number
  task_count?: number
  fail_count?: number
  established_at?: number
  last_beacon?: number
  target?: string
}

export interface C2Task {
  task_id: string
  channel_id: string
  command?: string
  params?: Record<string, unknown>
  status?: string
  result?: Record<string, unknown> | null
  received_at?: number
}

export interface AttackGraph {
  nodes: Array<Record<string, unknown>>
  edges: Array<{ from: string; to: string }>
  outcomes: Array<Record<string, unknown>>
  error?: string
}

export const api = {
  health: () => request<HealthResponse>('/api/health'),
  status: () => request<Status>('/api/status'),
  targets: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<{ targets: TargetHost[]; count: number }>(`/api/targets${q}`)
  },
  target: (id: string) =>
    request<{ host: TargetHost; findings: Finding[]; attack_paths: AttackGraph }>(
      `/api/targets/${encodeURIComponent(id)}`,
    ),
  findings: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<{ findings: Finding[]; count: number }>(`/api/findings${q}`)
  },
  searchFindings: (query: string, params?: Record<string, string>) => {
    const sp = new URLSearchParams({ query, ...(params || {}) })
    return request<{ findings: Finding[]; count: number }>(`/api/findings/search?${sp}`)
  },
  boneyardSummary: () =>
    request<{ total_items: number; categories: Record<string, number>; error?: string }>(
      '/api/boneyard/summary',
    ),
  boneyardCategories: () =>
    request<{ categories: string[]; count: number }>('/api/boneyard/categories'),
  integrity: () =>
    request<{
      verified: boolean
      total_rows_checked: number
      broken_hmacs: unknown[]
      table_counts: Record<string, number>
    }>('/api/boneyard/integrity'),
  attackGraph: (hostId?: string) => {
    const q = hostId ? `?host_id=${encodeURIComponent(hostId)}` : ''
    return request<AttackGraph>(`/api/attack-graph${q}`)
  },
  channels: () => request<{ channels: Channel[]; count: number }>('/api/c2/channels'),
  channel: (id: string) => request<Channel>(`/api/c2/channels/${encodeURIComponent(id)}`),
  channelHealth: (id: string) =>
    request<{ healthy: boolean; status?: string; reason?: string }>(
      `/api/c2/channels/${encodeURIComponent(id)}/health`,
    ),
  tasks: (status?: string) => {
    const q = status ? `?status=${encodeURIComponent(status)}` : ''
    return request<{ tasks: C2Task[]; count: number }>(`/api/c2/tasks${q}`)
  },
  warlogEntries: (params?: Record<string, string>) => {
    const q = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<{ entries: WarLogEntry[]; count: number }>(`/api/warlog/entries${q}`)
  },
  warlogSummary: () =>
    request<{
      session_id?: string
      total_entries: number
      duration_seconds: number
      level_counts: Record<string, number>
    }>('/api/warlog/summary'),
  warlogExport: () =>
    request<{ path: string; entries: number }>('/api/warlog/export', { method: 'POST' }),
  warlogDownload: () => download('/api/warlog/export/download'),
  reportPreview: (operator = 'THE VOID', name = 'Engagement Report') => {
    const sp = new URLSearchParams({ operator, engagement_name: name })
    return request<Record<string, unknown>>(`/api/report/preview?${sp}`)
  },
  reportGenerate: (body: {
    format: string
    operator?: string
    engagement_name?: string
  }) =>
    request<{ format: string; content: string; path?: string }>('/api/report/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  // ─── Insights engine (W1 backend → R-1/R-2/R-3/R-4/R-6) ───────────────────
  coverage: () => request<CoverageResponse>('/api/coverage'),
  mitre: () => request<MitreResponse>('/api/mitre'),
  compliance: () => request<ComplianceResponse>('/api/compliance'),
  drift: () => request<DriftResponse>('/api/drift'),
  scenarios: () => request<ScenariosResponse>('/api/scenarios'),

  // ─── DEMO MODE (W3) ────────────────────────────────────────────────────────
  demoStatus: () => request<DemoStatus>('/api/demo'),
  demoEnable: () =>
    request<DemoStatus>('/api/demo/enable', { method: 'POST' }),
  demoDisable: () =>
    request<DemoStatus>('/api/demo/disable', { method: 'POST' }),
}

export function wsUrl(): string {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  // In dev, Vite proxies /ws to backend
  return `${proto}://${window.location.host}/ws/live`
}
