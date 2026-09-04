import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, type WarLogEntry } from '../api/client'
import { Panel, EmptyState, ErrorState, LoadingState } from '../components/common/Panel'
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
  const [error, setError] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    setError(null)
    const params: Record<string, string> = { limit: '500' }
    if (level) params.level = level
    if (module) params.module = module
    api
      .warlogEntries(params)
      .then((r) => setEntries(r.entries))
      .catch((reason) => {
        setEntries([])
        setError(reason instanceof Error ? reason.message : String(reason))
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [level])

  const modules = useMemo(() => {
    const s = new Set<string>()
    for (const e of entries) {
      if (e.module) s.add(e.module)
    }
    return Array.from(s).sort()
  }, [entries])

  const filtered = module ? entries.filter((e) => (e.module || '') === module) : entries

  const doExport = useCallback(async () => {
    try {
      setExportMsg('Preparing download…')
      const blob = await api.warlogDownload()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'warlog_export.json'
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      setExportMsg(`Downloaded ${entries.length} visible entries (full WarLog export).`)
    } catch (e) {
      setExportMsg(String(e))
    }
  }, [entries.length])

  useEffect(() => {
    const onExport = () => void doExport()
    window.addEventListener('void:export-warlog', onExport)
    return () => window.removeEventListener('void:export-warlog', onExport)
  }, [doExport])

  return (
    <Panel
      title="WarLog Viewer"
      className="h-full"
      bodyClassName="!p-0 flex flex-col"
      actions={
        <>
          <select aria-label="Filter WarLog by level" className="void-input" value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="">All levels</option>
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
          <select
            className="void-input"
            aria-label="Filter WarLog by module"
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
            Download JSON
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
      {!loading && error ? (
        <div className="p-3"><ErrorState message={error} onRetry={load} /></div>
      ) : !loading && filtered.length === 0 ? (
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
