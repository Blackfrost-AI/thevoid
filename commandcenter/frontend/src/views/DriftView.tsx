import { useCallback, useEffect, useState } from 'react'
import { Panel, Stat, EmptyState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { fmtEpoch, fmtTs } from '../utils/format'
import { api } from '../api/client'
import type { DriftResponse, DriftEvent } from '../types/insights'

const REFRESH_MS = 30_000

function phaseCount(ev: DriftEvent): number {
  const p = ev.data?.phases
  return p && typeof p === 'object' ? Object.keys(p).length : 0
}

export function DriftView() {
  const openInspector = useUiStore((s) => s.openInspector)
  const [data, setData] = useState<DriftResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      setData(await api.drift())
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, REFRESH_MS)
    return () => clearInterval(t)
  }, [load])

  const targets = new Set(
    (data?.events ?? []).map((e) => e.data?.target).filter(Boolean) as string[],
  )

  const inspect = (ev: DriftEvent) =>
    openInspector({
      title: `Drift — ${ev.data?.target || ev.id}`,
      subtitle: ev.data?.kind || 'drift event',
      fields: [
        { label: 'Event ID', value: String(ev.id) },
        { label: 'Kind', value: ev.data?.kind || '—' },
        { label: 'Target', value: ev.data?.target || '—' },
        { label: 'Phases drifted', value: phaseCount(ev) },
        { label: 'Tags', value: (ev.tags || []).join(', ') || '—' },
        { label: 'Recorded', value: ev.timestamp ? fmtTs(ev.timestamp) : fmtEpoch(ev.epoch) },
      ],
      json: ev,
    })

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <Panel title="Continuity Drift (R-3)">
          <div className="flex flex-wrap gap-5">
            <Stat label="Events" value={data?.count ?? '—'} tone={data?.count ? 'warning' : undefined} />
            <Stat label="Targets" value={targets.size || '—'} tone="info" />
          </div>
          <div className="mt-3 text-[11px] text-void-text-mute">
            Drift events are persisted by the ContinuityScheduler into the Boneyard when a target's
            engagement state diverges from expectations.
          </div>
          {error ? <div className="mt-2 text-[11px] text-void-error">{error}</div> : null}
        </Panel>

        <Panel title="Latest Event" className="xl:col-span-3">
          {data && data.events.length > 0 ? (
            <div className="flex flex-wrap gap-5 items-baseline">
              <span className="mono text-[15px] text-void-warning">
                {data.events[0].data?.target || String(data.events[0].id)}
              </span>
              <span className="badge warning">{data.events[0].data?.kind || 'drift'}</span>
              <span className="text-[11px] text-void-text-dim">
                {data.events[0].timestamp
                  ? fmtTs(data.events[0].timestamp)
                  : fmtEpoch(data.events[0].epoch)}
              </span>
              <span className="text-[11px] text-void-text-mute">
                {phaseCount(data.events[0])} phase(s) drifted
              </span>
            </div>
          ) : (
            <EmptyState message="No drift recorded yet — stability intact." />
          )}
        </Panel>
      </div>

      <Panel
        title="Drift Event Timeline"
        className="flex-1 min-h-[280px]"
        bodyClassName="!p-0 overflow-auto"
        actions={
          <button type="button" className="void-btn" onClick={load} disabled={busy}>
            {busy ? 'Loading…' : 'Refresh'}
          </button>
        }
      >
        {!data ? (
          <div className="p-3">
            <EmptyState message={busy ? 'Loading drift events…' : 'Loading…'} />
          </div>
        ) : data.events.length === 0 ? (
          <div className="p-3">
            <EmptyState message="No drift events in the Boneyard. The continuity scheduler has not flagged any divergence." />
          </div>
        ) : (
          <table className="void-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Target</th>
                <th>Kind</th>
                <th>Phases</th>
                <th>Tags</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((ev) => (
                <tr
                  key={String(ev.id)}
                  className="drift-row cursor-pointer"
                  onClick={() => inspect(ev)}
                >
                  <td className="mono text-void-text-dim">
                    {ev.timestamp ? fmtTs(ev.timestamp) : fmtEpoch(ev.epoch)}
                  </td>
                  <td className="text-void-warning">{ev.data?.target || '—'}</td>
                  <td>
                    <span className="badge warning">{ev.data?.kind || 'drift'}</span>
                  </td>
                  <td className="mono">{phaseCount(ev)}</td>
                  <td className="text-void-text-mute">{(ev.tags || []).join(', ') || '—'}</td>
                  <td className="mono text-void-text-mute">{String(ev.id)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
