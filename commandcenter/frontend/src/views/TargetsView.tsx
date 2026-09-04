import { useEffect, useState } from 'react'
import { api, type TargetHost } from '../api/client'
import { Panel, EmptyState, LoadingState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { statusClass, trunc } from '../utils/format'

export function TargetsView() {
  const [targets, setTargets] = useState<TargetHost[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const selectedId = useUiStore((s) => s.selectedId)
  const setSelectedId = useUiStore((s) => s.setSelectedId)
  const openInspector = useUiStore((s) => s.openInspector)

  const load = () => {
    setLoading(true)
    api
      .targets()
      .then((r) => {
        setTargets(r.targets)
        setError(null)
      })
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
  }, [])

  const filtered = targets.filter((t) => {
    if (!filter) return true
    const q = filter.toLowerCase()
    return [t.ip_address, t.hostname, t.domain, t.status, t.id]
      .filter(Boolean)
      .some((v) => String(v).toLowerCase().includes(q))
  })

  const onSelect = async (t: TargetHost) => {
    const id = String(t.id || t.ip_address || t.hostname || '')
    setSelectedId(id)
    openInspector({
      title: t.hostname || t.ip_address || id,
      subtitle: t.ip_address,
      fields: [
        { label: 'ID', value: t.id },
        { label: 'IP', value: t.ip_address },
        { label: 'Hostname', value: t.hostname },
        { label: 'Domain', value: t.domain },
        { label: 'Status', value: t.status },
        { label: 'Critical', value: Boolean(t.is_critical) },
      ],
      json: t,
    })
    if (t.id) {
      try {
        const detail = await api.target(String(t.id))
        openInspector({
          title: detail.host.hostname || detail.host.ip_address || String(t.id),
          subtitle: detail.host.ip_address,
          fields: [
            { label: 'ID', value: detail.host.id },
            { label: 'IP', value: detail.host.ip_address },
            { label: 'Hostname', value: detail.host.hostname },
            { label: 'Domain', value: detail.host.domain },
            { label: 'Status', value: detail.host.status },
            { label: 'Findings', value: detail.findings.length },
            {
              label: 'Path nodes',
              value: detail.attack_paths?.nodes?.length ?? 0,
            },
          ],
          json: detail,
        })
      } catch {
        /* keep summary */
      }
    }
  }

  return (
    <Panel
      title="Target Management"
      className="h-full"
      bodyClassName="!p-0 flex flex-col"
      actions={
        <>
          <input
            className="void-input w-48"
            placeholder="Filter hosts…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button type="button" className="void-btn" onClick={load}>
            Refresh
          </button>
        </>
      }
    >
      {loading ? <div className="p-3"><LoadingState /></div> : null}
      {error ? <div className="p-3 text-void-error text-[12px]">{error}</div> : null}
      {!loading && !error && filtered.length === 0 ? (
        <div className="p-3">
          <EmptyState message="No hosts in Boneyard. Hosts appear after recon/engagement writes relational host records." />
        </div>
      ) : null}
      {filtered.length > 0 ? (
        <div className="overflow-auto flex-1">
          <table className="void-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Hostname</th>
                <th>Domain</th>
                <th>Status</th>
                <th>Critical</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => {
                const id = String(t.id || t.ip_address || '')
                return (
                  <tr
                    key={id}
                    className={selectedId === id ? 'selected' : ''}
                    onClick={() => onSelect(t)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="mono">{t.ip_address || '—'}</td>
                    <td>{t.hostname || '—'}</td>
                    <td className="text-void-text-dim">{t.domain || '—'}</td>
                    <td>
                      <span className={`badge ${statusClass(t.status)}`}>
                        {t.status || 'unknown'}
                      </span>
                    </td>
                    <td>{t.is_critical ? 'yes' : 'no'}</td>
                    <td className="mono text-void-text-mute">{trunc(t.id, 16)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </Panel>
  )
}
