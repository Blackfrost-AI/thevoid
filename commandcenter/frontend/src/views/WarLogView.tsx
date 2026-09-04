import { useEffect, useMemo, useState } from 'react'
import { api, type WarLogEntry } from '../api/client'
import { Panel, EmptyState, LoadingState } from '../components/common/Panel'
import { EventStream } from '../components/common/EventStream'

const LEVELS = [
  'agent',
  'info',
  'warning',
  'error',
  'critical',
  'recon',
  'exploit',
  'stealth',
  'exfil',
  'c2',
]

export function WarLogView() {
  const [entries, setEntries] = useState<WarLogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [level, setLevel] = useState('')
  const [module, setModule] = useState('')
  const [exportMsg, setExportMsg] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    const params: Record<string, string> = { limit: '500' }
    if (level) params.level = level
    if (module) params.module = module
    api
      .warlogEntries(params)
      .then((r) => setEntries(r.entries))
      .catch(() => setEntries([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [level])

  useEffect(() => {
    const onExport = () => doExport()
    window.addEventListener('void:export-warlog', onExport)
    return () => window.removeEventListener('void:export-warlog', onExport)
  })

  const modules = useMemo(() => {
    const s = new Set<string>()
    for (const e of entries) {
      if (e.module) s.add(e.module)
    }
    return Array.from(s).sort()
  }, [entries])

  const filtered = module ? entries.filter((e) => (e.module || '') === module) : entries

  const doExport = async () => {
    try {
      const r = await api.warlogExport()
      setExportMsg(`Exported ${r.entries} entries → ${r.path}`)
    } catch (e) {
      setExportMsg(String(e))
    }
  }

  return (
    <Panel
      title="WarLog Viewer"
      className="h-full"
      bodyClassName="!p-0 flex flex-col"
      actions={
        <>
          <select className="void-input" value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="">All levels</option>
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
          <select
            className="void-input"
            value={module}
            onChange={(e) => setModule(e.target.value)}
          >
            <option value="">All modules</option>
            {modules.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
          <button type="button" className="void-btn" onClick={load}>
            Refresh
          </button>
          <button type="button" className="void-btn primary" onClick={doExport}>
            Export
          </button>
        </>
      }
    >
      {exportMsg ? (
        <div className="px-3 py-2 text-[11px] text-void-info border-b border-void-line mono">
          {exportMsg}
        </div>
      ) : null}
      {loading ? (
        <div className="p-3">
          <LoadingState />
        </div>
      ) : null}
      {!loading && filtered.length === 0 ? (
        <div className="p-3">
          <EmptyState message="No warlog entries." />
        </div>
      ) : (
        <div className="flex-1 min-h-0">
          <EventStream entries={filtered} live={false} maxRows={500} />
        </div>
      )}
    </Panel>
  )
}
