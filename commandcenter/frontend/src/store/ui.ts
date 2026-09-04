import { create } from 'zustand'

export type ViewId =
  | 'dashboard'
  | 'targets'
  | 'boneyard'
  | 'graph'
  | 'timeline'
  | 'c2'
  | 'warlog'
  | 'reports'
  | 'prevention'
  | 'compliance'
  | 'drift'
  | 'settings'

export interface InspectorPayload {
  title: string
  subtitle?: string
  fields?: Array<{ label: string; value: string | number | boolean | null | undefined }>
  json?: unknown
  actions?: Array<{ label: string; onClick: () => void }>
}

interface UiState {
  view: ViewId
  inspectorOpen: boolean
  inspector: InspectorPayload | null
  commandPaletteOpen: boolean
  selectedId: string | null
  setView: (v: ViewId) => void
  openInspector: (payload: InspectorPayload) => void
  closeInspector: () => void
  setCommandPalette: (open: boolean) => void
  setSelectedId: (id: string | null) => void
}

export const useUiStore = create<UiState>((set) => ({
  view: 'dashboard',
  inspectorOpen: true,
  inspector: null,
  commandPaletteOpen: false,
  selectedId: null,
  setView: (view) => set({ view, selectedId: null, inspector: null }),
  openInspector: (inspector) => set({ inspector, inspectorOpen: true }),
  closeInspector: () => set({ inspector: null }),
  setCommandPalette: (commandPaletteOpen) => set({ commandPaletteOpen }),
  setSelectedId: (selectedId) => set({ selectedId }),
}))

export const NAV_ITEMS: Array<{ id: ViewId; label: string; short: string }> = [
  { id: 'dashboard', label: 'Operations', short: 'Ops' },
  { id: 'targets', label: 'Targets', short: 'Tgt' },
  { id: 'boneyard', label: 'Boneyard', short: 'Bone' },
  { id: 'graph', label: 'Attack Graph', short: 'Graph' },
  { id: 'timeline', label: 'Timeline', short: 'Time' },
  { id: 'c2', label: 'C2 Channels', short: 'C2' },
  { id: 'warlog', label: 'WarLog', short: 'Logs' },
  { id: 'reports', label: 'Reports', short: 'Rpt' },
  { id: 'prevention', label: 'Prevention', short: 'Prev' },
  { id: 'compliance', label: 'Compliance', short: 'Comp' },
  { id: 'drift', label: 'Drift', short: 'Drft' },
  { id: 'settings', label: 'Settings', short: 'Cfg' },
]
