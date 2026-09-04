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

export const VIEW_PATHS: Record<ViewId, string> = {
  dashboard: '/operations',
  targets: '/targets',
  boneyard: '/boneyard',
  graph: '/attack-graph',
  timeline: '/timeline',
  c2: '/c2-channels',
  warlog: '/warlog',
  reports: '/reports',
  prevention: '/prevention',
  compliance: '/compliance',
  drift: '/drift',
  settings: '/settings',
}

const PATH_VIEWS = new Map<string, ViewId>(
  Object.entries(VIEW_PATHS).map(([view, path]) => [path, view as ViewId]),
)

export function viewFromPathname(pathname: string): ViewId {
  const normalized = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  return PATH_VIEWS.get(normalized) ?? 'dashboard'
}

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
  mobileNavOpen: boolean
  selectedId: string | null
  setView: (v: ViewId, historyMode?: 'push' | 'replace' | 'none') => void
  openInspector: (payload: InspectorPayload) => void
  closeInspector: () => void
  setCommandPalette: (open: boolean) => void
  setMobileNav: (open: boolean) => void
  setSelectedId: (id: string | null) => void
}

export const useUiStore = create<UiState>((set) => ({
  view:
    typeof window === 'undefined' ? 'dashboard' : viewFromPathname(window.location.pathname),
  inspectorOpen: false,
  inspector: null,
  commandPaletteOpen: false,
  mobileNavOpen: false,
  selectedId: null,
  setView: (view, historyMode = 'push') => {
    if (typeof window !== 'undefined' && historyMode !== 'none') {
      const path = VIEW_PATHS[view]
      if (window.location.pathname !== path) {
        const method = historyMode === 'replace' ? 'replaceState' : 'pushState'
        window.history[method]({ view }, '', path)
      }
    }
    set({
      view,
      selectedId: null,
      inspector: null,
      inspectorOpen: false,
      mobileNavOpen: false,
    })
  },
  openInspector: (inspector) => set({ inspector, inspectorOpen: true }),
  closeInspector: () => set({ inspector: null, inspectorOpen: false }),
  setCommandPalette: (commandPaletteOpen) => set({ commandPaletteOpen }),
  setMobileNav: (mobileNavOpen) => set({ mobileNavOpen }),
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
