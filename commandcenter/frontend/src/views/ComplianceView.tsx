import { useCallback, useEffect, useMemo, useState } from 'react'
import { Panel, EmptyState, ErrorState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { api } from '../api/client'
import type { ComplianceResponse, MitreResponse } from '../types/insights'

const REFRESH_MS = 30_000

const FRAMEWORKS = ['nist', 'pci', 'iso'] as const

export function ComplianceView() {
  const openInspector = useUiStore((s) => s.openInspector)
  const [compliance, setCompliance] = useState<ComplianceResponse | null>(null)
  const [mitre, setMitre] = useState<MitreResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const [c, m] = await Promise.all([api.compliance(), api.mitre()])
      setCompliance(c)
      setMitre(m)
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

  // technique id → display name from the MITRE annotation (if present)
  const techNames = useMemo(() => {
    const map: Record<string, string> = {}
    for (const t of mitre?.techniques_used ?? []) map[t.id] = t.name
    return map
  }, [mitre])

  const rows = useMemo(() => {
    const ids = Object.keys(compliance?.compliance ?? {})
    const q = query.trim().toLowerCase()
    return ids
      .filter((id) => !q || id.toLowerCase().includes(q) || (techNames[id] || '').toLowerCase().includes(q))
      .sort()
  }, [compliance, techNames, query])

  const inspectRow = (id: string) =>
    openInspector({
      title: `${id} — ${techNames[id] || 'mapped technique'}`,
      subtitle: 'compliance cross-reference',
      fields: [
        { label: 'Technique', value: id },
        { label: 'NIST CSF', value: compliance?.compliance[id]?.nist || '—' },
        { label: 'PCI DSS', value: compliance?.compliance[id]?.pci || '—' },
        { label: 'ISO 27001', value: compliance?.compliance[id]?.iso || '—' },
      ],
      json: compliance?.compliance[id],
    })

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <Panel title="Framework Overlay" className="xl:col-span-2">
          <div className="flex flex-wrap gap-4 text-[11px] text-void-text-dim">
            <span className="badge info">NIST CSF 1.1</span>
            <span className="badge warning">PCI DSS 4.0</span>
            <span className="badge success">ISO/IEC 27001:2022</span>
          </div>
          {compliance?.note ? (
            <div className="mt-3 text-[11px] text-void-text-mute border border-void-line rounded px-3 py-2">
              {compliance.note}
            </div>
          ) : null}
        </Panel>

        <Panel title="Mapped Techniques">
          <div className="flex items-baseline gap-2">
            <span className="text-[26px] font-semibold mono text-void-info">
              {compliance ? Object.keys(compliance.compliance).length : '—'}
            </span>
            <span className="text-[11px] text-void-text-mute">
              of {compliance?.techniques_used.length ?? 0} observed
            </span>
          </div>
          <div className="mt-3 flex gap-2">
            <input
              className="void-input flex-1"
              aria-label="Filter compliance techniques"
              placeholder="Filter technique / name…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <button type="button" className="void-btn" onClick={load} disabled={busy}>
              Refresh
            </button>
          </div>
        </Panel>
      </div>

      <Panel
        title="Compliance Cross-Reference"
        className="flex-1 min-h-[280px]"
        bodyClassName="!p-0 overflow-auto"
      >
        {error ? (
          <div className="p-3">
            <ErrorState message={error} onRetry={load} />
          </div>
        ) : !compliance ? (
          <div className="p-3">
            <EmptyState message={busy ? 'Loading cross-reference…' : 'No compliance data yet.'} />
          </div>
        ) : Object.keys(compliance.compliance).length === 0 ? (
          <div className="p-3">
            <EmptyState message="No mapped techniques — compliance overlay is honest-empty until an engagement maps techniques." />
          </div>
        ) : (
          <table className="void-table">
            <thead>
              <tr>
                <th>Technique</th>
                <th>Name</th>
                <th>NIST CSF</th>
                <th>PCI DSS</th>
                <th>ISO 27001</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((id) => {
                const ref = compliance.compliance[id]
                return (
                  <tr
                    key={id}
                    className="cursor-pointer"
                    onClick={() => inspectRow(id)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        inspectRow(id)
                      }
                    }}
                    tabIndex={0}
                  >
                    <td className="mono text-void-info">{id}</td>
                    <td>{techNames[id] || '—'}</td>
                    {FRAMEWORKS.map((fw) => (
                      <td key={fw} className={ref?.[fw] ? '' : 'text-void-text-mute'}>
                        {ref?.[fw] || '—'}
                      </td>
                    ))}
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
