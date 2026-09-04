import { useEffect, useState } from 'react'
import { api, type Channel } from '../api/client'
import { Panel, EmptyState, LoadingState, Stat } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { fmtEpoch, statusClass } from '../utils/format'

export function C2View() {
  const [channels, setChannels] = useState<Channel[]>([])
  const [tasks, setTasks] = useState<unknown[]>([])
  const [loading, setLoading] = useState(true)
  const selectedId = useUiStore((s) => s.selectedId)
  const setSelectedId = useUiStore((s) => s.setSelectedId)
  const openInspector = useUiStore((s) => s.openInspector)

  const load = async () => {
    setLoading(true)
    try {
      const [ch, tk] = await Promise.all([api.channels(), api.tasks()])
      setChannels(ch.channels)
      setTasks(tk.tasks)
    } catch {
      setChannels([])
      setTasks([])
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
        { label: 'Target', value: c.target },
        { label: 'Endpoint', value: c.endpoint },
        { label: 'Beacons', value: c.beacon_count },
        { label: 'Tasks', value: c.task_count },
        { label: 'Fails', value: c.fail_count },
        { label: 'Last beacon', value: fmtEpoch(c.last_beacon) },
      ],
      json: c,
    })
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

  const active = channels.filter((c) => c.status === 'active').length

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-3 gap-3">
        <Panel title="Channel Summary">
          <div className="flex gap-6">
            <Stat label="Total" value={channels.length} />
            <Stat label="Active" value={active} tone="success" />
            <Stat label="Tasks" value={tasks.length} tone="info" />
          </div>
        </Panel>
        <Panel title="Health" className="col-span-2">
          <p className="text-[12px] text-void-text-dim">
            Select a channel to run a live health check. Channels are established in-process via
            MCPC2; an empty list means no C2 channels in this command-center process yet.
          </p>
        </Panel>
      </div>

      <Panel
        title="C2 Channels"
        className="flex-1 min-h-0"
        bodyClassName="!p-0"
        actions={
          <button type="button" className="void-btn" onClick={load}>
            Refresh
          </button>
        }
      >
        {loading ? <div className="p-3"><LoadingState /></div> : null}
        {!loading && channels.length === 0 ? (
          <div className="p-3">
            <EmptyState message="No C2 channels in this process. Establish channels via MCPC2 or load from engagement state." />
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
    </div>
  )
}
