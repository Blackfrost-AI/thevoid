import { useEffect } from 'react'
import { Shell } from './components/shell/Shell'
import { CommandPalette } from './components/command/CommandPalette'
import { useUiStore } from './store/ui'
import { useEngagementStore } from './store/engagement'
import { useWsStore } from './store/websocket'
import { useDemoStore } from './store/demo'
import { DashboardView } from './views/DashboardView'
import { TargetsView } from './views/TargetsView'
import { BoneyardView } from './views/BoneyardView'
import { GraphView } from './views/GraphView'
import { TimelineView } from './views/TimelineView'
import { C2View } from './views/C2View'
import { WarLogView } from './views/WarLogView'
import { ReportsView } from './views/ReportsView'
import { PreventionView } from './views/PreventionView'
import { ComplianceView } from './views/ComplianceView'
import { DriftView } from './views/DriftView'
import { SettingsView } from './views/SettingsView'

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
  const fetchStatus = useEngagementStore((s) => s.fetchStatus)
  const connect = useWsStore((s) => s.connect)
  const disconnect = useWsStore((s) => s.disconnect)
  const demoRefresh = useDemoStore((s) => s.refresh)

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

  return (
    <>
      <Shell>
        <ActiveView />
      </Shell>
      <CommandPalette />
    </>
  )
}
