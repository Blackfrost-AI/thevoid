import { useEffect, useState } from 'react'
import { api, type C2Task, type Channel } from '../api/client'
import { Panel, EmptyState, ErrorState, LoadingState, Stat } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { fmtEpoch, statusClass } from '../utils/format'

export function C2View() {
  const [channels, setChannels] = useState<Channel[]>([])
  const [tasks, setTasks] = useState<C2Task[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const selectedId = useUiStore((s) => s.selectedId)
  const setSelectedId = useUiStore((s) => s.setSelectedId)
  const openInspector = useUiStore((s) => s.openInspector)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const [ch, tk] = await Promise.all([api.channels(), api.tasks()])
      setChannels(ch.channels)
      setTasks(tk.tasks)
    } catch (reason) {
      setChannels([])
      setTasks([])
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [])

  const onSelect = async (c: Channel) => {
    setSelectedId(c.channel_id)
    openInspector({
      title: c.channel_id,
      subtitle: c.target || c.endpoint,
      fields: [
        { label: 'Status', value: c.status },
        { label: 'Source', value: c.live ? 'Live process' : 'Recorded evidence' },
        { label: 'Last known status', value: c.last_known_status },
        { label: 'Target', value: c.target },
        { label: 'Endpoint', value: c.endpoint },
        { label: 'Beacons', value: c.beacon_count },
        { label: 'Tasks', value: c.task_count },
        { label: 'Fails', value: c.fail_count },
        { label: 'Last beacon', value: fmtEpoch(c.last_beacon) },
      ],
      json: c,
    })
    if (!c.live) return
    try {
      const health = await api.channelHealth(c.channel_id)
      openInspector({
        title: c.channel_id,
        subtitle: c.target || c.endpoint,
        fields: [
          { label: 'Status', value: c.status },
          { label: 'Healthy', value: health.healthy },
          { label: 'Health status', value: health.status },
          { label: 'Reason', value: health.reason },
          { label: 'Beacons', value: c.beacon_count },
          { label: 'Tasks', value: c.task_count },
          { label: 'Last beacon', value: fmtEpoch(c.last_beacon) },
        ],
        json: { channel: c, health },
      })
    } catch {
      /* channel detail only */
    }
  }

  const active = channels.filter((c) => c.live && c.status === 'active').length
  const recorded = channels.filter((c) => !c.live).length

  const onTaskSelect = (task: C2Task) => {
    setSelectedId(task.task_id)
    openInspector({
      title: task.command || task.task_id,
      subtitle: task.task_id,
      fields: [
        { label: 'Status', value: task.status },
        { label: 'Channel', value: task.channel_id },
        { label: 'Received', value: fmtEpoch(task.received_at) },
      ],
      json: task,
    })
  }

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <Panel title="Channel Summary">
          <div className="flex flex-wrap gap-6">
            <Stat label="Total" value={channels.length} />
            <Stat label="Live" value={active} tone="success" />
            <Stat label="Recorded" value={recorded} tone="info" />
            <Stat label="Tasks" value={tasks.length} tone="info" />
          </div>
        </Panel>
        <Panel title="Health" className="lg:col-span-2">
          <p className="text-[12px] text-void-text-dim">
            Select a live channel to run a health check. Recorded evidence remains visible after
            an operator process exits and is never presented as a currently reachable channel.
          </p>
        </Panel>
      </div>

      <div className="flex-1 min-h-0 grid grid-cols-1 xl:grid-cols-3 gap-3">
        <Panel
          title="C2 Channels"
          className="xl:col-span-2 min-h-[240px]"
          bodyClassName="!p-0"
          actions={
            <button type="button" className="void-btn" onClick={load}>
              Refresh
            </button>
          }
        >
          {loading ? <div className="p-3"><LoadingState /></div> : null}
          {!loading && error ? (
            <div className="p-3"><ErrorState message={error} onRetry={() => void load()} /></div>
          ) : !loading && channels.length === 0 ? (
            <div className="p-3">
              <EmptyState message="No live channels or recorded channel evidence yet." />
            </div>
          ) : (
            <div className="overflow-auto">
              <table className="void-table">
                <thead>
                  <tr>
                    <th>Channel</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Beacons</th>
                    <th>Tasks</th>
                    <th>Last Beacon</th>
                  </tr>
                </thead>
                <tbody>
                  {channels.map((c) => (
                    <tr
                      key={c.channel_id}
                      className={selectedId === c.channel_id ? 'selected' : ''}
                      onClick={() => onSelect(c)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          void onSelect(c)
                        }
                      }}
                      tabIndex={0}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="mono">{c.channel_id}</td>
                      <td>{c.target || '—'}</td>
                      <td>
                        <span className={`badge ${statusClass(c.status)}`}>{c.status}</span>
                      </td>
                      <td className="mono">{c.beacon_count ?? 0}</td>
                      <td className="mono">{c.task_count ?? 0}</td>
                      <td className="mono text-void-text-dim">{fmtEpoch(c.last_beacon)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        <Panel title="Tasks" className="min-h-[240px]" bodyClassName="!p-0 overflow-auto">
          {!loading && tasks.length === 0 ? (
            <div className="p-3">
              <EmptyState message="No tasks observed in the connected runtime." />
            </div>
          ) : (
            <table className="void-table">
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Command</th>
                  <th>Received</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map((task) => (
                  <tr
                    key={task.task_id}
                    className={selectedId === task.task_id ? 'selected' : ''}
                    onClick={() => onTaskSelect(task)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        onTaskSelect(task)
                      }
                    }}
                    tabIndex={0}
                    style={{ cursor: 'pointer' }}
                  >
                    <td><span className={`badge ${statusClass(task.status)}`}>{task.status || 'unknown'}</span></td>
                    <td className="mono">{task.command || '—'}</td>
                    <td className="mono text-void-text-dim">{fmtEpoch(task.received_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </div>
  )
}
