import { lazy, Suspense, useEffect } from 'react'
import { Shell } from './components/shell/Shell'
import { CommandPalette } from './components/command/CommandPalette'
import { NAV_ITEMS, useUiStore, viewFromPathname } from './store/ui'
import { useEngagementStore } from './store/engagement'
import { useWsStore } from './store/websocket'
import { useDemoStore } from './store/demo'

const DashboardView = lazy(() =>
  import('./views/DashboardView').then((module) => ({ default: module.DashboardView })),
)
const TargetsView = lazy(() =>
  import('./views/TargetsView').then((module) => ({ default: module.TargetsView })),
)
const BoneyardView = lazy(() =>
  import('./views/BoneyardView').then((module) => ({ default: module.BoneyardView })),
)
const GraphView = lazy(() =>
  import('./views/GraphView').then((module) => ({ default: module.GraphView })),
)
const TimelineView = lazy(() =>
  import('./views/TimelineView').then((module) => ({ default: module.TimelineView })),
)
const C2View = lazy(() =>
  import('./views/C2View').then((module) => ({ default: module.C2View })),
)
const WarLogView = lazy(() =>
  import('./views/WarLogView').then((module) => ({ default: module.WarLogView })),
)
const ReportsView = lazy(() =>
  import('./views/ReportsView').then((module) => ({ default: module.ReportsView })),
)
const PreventionView = lazy(() =>
  import('./views/PreventionView').then((module) => ({ default: module.PreventionView })),
)
const ComplianceView = lazy(() =>
  import('./views/ComplianceView').then((module) => ({ default: module.ComplianceView })),
)
const DriftView = lazy(() =>
  import('./views/DriftView').then((module) => ({ default: module.DriftView })),
)
const SettingsView = lazy(() =>
  import('./views/SettingsView').then((module) => ({ default: module.SettingsView })),
)

function ActiveView() {
  const view = useUiStore((s) => s.view)
  switch (view) {
    case 'dashboard':
      return <DashboardView />
    case 'targets':
      return <TargetsView />
    case 'boneyard':
      return <BoneyardView />
    case 'graph':
      return <GraphView />
    case 'timeline':
      return <TimelineView />
    case 'c2':
      return <C2View />
    case 'warlog':
      return <WarLogView />
    case 'reports':
      return <ReportsView />
    case 'prevention':
      return <PreventionView />
    case 'compliance':
      return <ComplianceView />
    case 'drift':
      return <DriftView />
    case 'settings':
      return <SettingsView />
    default:
      return <DashboardView />
  }
}

export default function App() {
  const view = useUiStore((s) => s.view)
  const viewLabel = NAV_ITEMS.find((item) => item.id === view)?.label ?? 'Operations'
  const setView = useUiStore((s) => s.setView)
  const fetchStatus = useEngagementStore((s) => s.fetchStatus)
  const statusError = useEngagementStore((s) => s.error)
  const connect = useWsStore((s) => s.connect)
  const disconnect = useWsStore((s) => s.disconnect)
  const demoRefresh = useDemoStore((s) => s.refresh)
  const demoError = useDemoStore((s) => s.error)

  useEffect(() => {
    fetchStatus()
    connect()
    void demoRefresh()
    const onRefresh = () => fetchStatus()
    window.addEventListener('void:refresh', onRefresh)
    const interval = setInterval(fetchStatus, 10000)
    return () => {
      window.removeEventListener('void:refresh', onRefresh)
      clearInterval(interval)
      disconnect()
    }
  }, [fetchStatus, connect, disconnect, demoRefresh])

  useEffect(() => {
    const onPopState = () => setView(viewFromPathname(window.location.pathname), 'none')
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [setView])

  useEffect(() => {
    document.title = `${viewLabel} — THE VOID Command Center`
  }, [viewLabel])

  return (
    <>
      <Shell>
        <div className="h-full flex flex-col gap-3">
          <h1 className="sr-only">{viewLabel}</h1>
          {statusError || demoError ? (
            <div
              role="alert"
              className="connection-alert shrink-0 flex flex-wrap items-center gap-3 rounded border border-void-error/50 bg-void-error/5 px-3 py-2 text-[12px] text-void-error"
            >
              <span>Command Center data is unavailable: {statusError || demoError}</span>
              <button type="button" className="void-btn ml-auto" onClick={() => void fetchStatus()}>
                Retry
              </button>
            </div>
          ) : null}
          <div className="flex-1 min-h-0">
            <Suspense
              fallback={
                <div role="status" aria-live="polite" className="p-3 text-void-text-dim">
                  Loading workspace…
                </div>
              }
            >
              <ActiveView />
            </Suspense>
          </div>
        </div>
      </Shell>
      <CommandPalette />
    </>
  )
}
