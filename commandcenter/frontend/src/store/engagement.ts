import { create } from 'zustand'
import type { Status, WarLogEntry, AttackGraph } from '../api/client'
import { api } from '../api/client'

interface Metrics {
  ts?: number
  uptime_seconds?: number
  events_per_minute?: number
  warlog_entries?: number
  session_id?: string
  c2_channels?: number
  c2_beacons?: number
  ws_clients?: number
  level_counts?: Record<string, number>
}

interface EngagementState {
  status: Status | null
  warlogLive: WarLogEntry[]
  metrics: Metrics | null
  metricsHistory: Array<{ t: number; rate: number }>
  latencyMs: number | null
  loading: boolean
  error: string | null
  // Live attack graph (WS channel `attack_graph`)
  attackGraph: AttackGraph | null
  pulseIds: Record<string, number>
  lastNodeEvent: number | null
  fetchStatus: () => Promise<void>
  fetchAttackGraph: () => Promise<void>
  pushWarlog: (entry: WarLogEntry) => void
  setMetrics: (m: Metrics) => void
  setLatency: (ms: number | null) => void
  applyEngagementUpdate: (s: Status) => void
  applyAttackGraphFull: (g: AttackGraph) => void
  applyAttackNode: (node: Record<string, unknown>) => void
}

export const useEngagementStore = create<EngagementState>((set, get) => ({
  status: null,
  warlogLive: [],
  metrics: null,
  metricsHistory: [],
  latencyMs: null,
  loading: false,
  error: null,
  attackGraph: null,
  pulseIds: {},
  lastNodeEvent: null,

  fetchStatus: async () => {
    set({ loading: true, error: null })
    const t0 = performance.now()
    try {
      const status = await api.status()
      set({
        status,
        loading: false,
        latencyMs: Math.round(performance.now() - t0),
      })
    } catch (e) {
      set({
        loading: false,
        error: e instanceof Error ? e.message : String(e),
        latencyMs: null,
      })
    }
  },

  fetchAttackGraph: async () => {
    try {
      const g = await api.attackGraph()
      set({ attackGraph: g, lastNodeEvent: Date.now() })
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) })
    }
  },

  pushWarlog: (entry) => {
    const prev = get().warlogLive
    const next = [entry, ...prev].slice(0, 200)
    set({ warlogLive: next })
  },

  setMetrics: (m) => {
    const hist = get().metricsHistory
    const point = { t: m.ts || Date.now() / 1000, rate: m.events_per_minute || 0 }
    set({
      metrics: m,
      metricsHistory: [...hist, point].slice(-60),
    })
  },

  setLatency: (ms) => set({ latencyMs: ms }),

  applyEngagementUpdate: (s) => set({ status: s }),

  applyAttackGraphFull: (g) => {
    const now = Date.now()
    const prev = get().attackGraph
    const prevIds = new Set((prev?.nodes || []).map((n) => String((n as { id?: unknown }).id)))
    const pulses: Record<string, number> = {}
    for (const n of g?.nodes || []) {
      const id = String((n as { id?: unknown }).id)
      if (!prevIds.has(id)) pulses[id] = now
    }
    set({
      attackGraph: g,
      pulseIds: { ...get().pulseIds, ...pulses },
      lastNodeEvent: now,
    })
  },

  applyAttackNode: (node) => {
    const now = Date.now()
    const id = String((node as { id?: unknown }).id)
    const prev = get().attackGraph || { nodes: [], edges: [], outcomes: [] }
    const nodes = [...(prev.nodes || [])]
    const idx = nodes.findIndex((n) => String((n as { id?: unknown }).id) === id)
    if (idx >= 0) nodes[idx] = node
    else nodes.push(node)
    // Derive parent edge so the link appears immediately.
    const edges = [...(prev.edges || [])]
    const parent = (node as { parent_step_id?: unknown }).parent_step_id
    if (parent && !edges.some((e) => e.from === String(parent) && e.to === id)) {
      edges.push({ from: String(parent), to: id })
    }
    set({
      attackGraph: { ...prev, nodes, edges },
      pulseIds: { ...get().pulseIds, [id]: now },
      lastNodeEvent: now,
    })
  },
}))
