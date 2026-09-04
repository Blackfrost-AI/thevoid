import { useEffect, useState } from 'react'
import { api, type Finding } from '../api/client'
import { Panel, EmptyState, ErrorState, LoadingState, Stat } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { trunc } from '../utils/format'

export function BoneyardView() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [summary, setSummary] = useState<{ total_items: number; categories: Record<string, number> } | null>(null)
  const [integrity, setIntegrity] = useState<{ verified: boolean; total_rows_checked: number } | null>(null)
  const [categories, setCategories] = useState<string[]>([])
  const [category, setCategory] = useState('')
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const selectedId = useUiStore((s) => s.selectedId)
  const setSelectedId = useUiStore((s) => s.setSelectedId)
  const openInspector = useUiStore((s) => s.openInspector)

  const load = async (selectedCategory = category) => {
    setLoading(true)
    setError(null)
    try {
      const params: Record<string, string> = { limit: '300' }
      if (selectedCategory) params.category = selectedCategory
      let rows: Finding[]
      if (query.trim()) {
        const r = await api.searchFindings(query.trim(), params)
        rows = r.findings
      } else {
        const r = await api.findings(params)
        rows = r.findings
      }
      setFindings(rows)
      const [sum, cats, integ] = await Promise.all([
        api.boneyardSummary(),
        api.boneyardCategories(),
        api.integrity(),
      ])
      setSummary(sum)
      setCategories(cats.categories)
      setIntegrity(integ)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const onSelect = (f: Finding) => {
    setSelectedId(String(f.id))
    openInspector({
      title: f.title || f.category || String(f.id),
      subtitle: f.id,
      fields: [
        { label: 'Category', value: f.category },
        { label: 'Risk', value: f.risk_score },
        { label: 'Tags', value: (f.tags || []).join(', ') },
        { label: 'Host', value: f.host_id },
        { label: 'Time', value: f.timestamp },
      ],
      json: f,
    })
  }

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Panel title="Inventory">
          <div className="flex gap-6">
            <Stat label="Items" value={summary?.total_items ?? '—'} tone="info" />
            <Stat label="Categories" value={Object.keys(summary?.categories || {}).length} />
          </div>
        </Panel>
        <Panel title="Integrity">
          <div className="flex items-center gap-3">
            <span className={`badge ${integrity?.verified ? 'success' : 'error'}`}>
              {integrity == null ? 'UNKNOWN' : integrity.verified ? 'VERIFIED' : 'TAMPERED'}
            </span>
            <span className="text-[12px] text-void-text-dim mono">
              rows checked: {integrity?.total_rows_checked ?? '—'}
            </span>
          </div>
        </Panel>
        <Panel title="Top Categories">
          <div className="flex flex-wrap gap-1 max-h-16 overflow-auto">
            {Object.entries(summary?.categories || {})
              .sort((a, b) => b[1] - a[1])
              .slice(0, 12)
              .map(([c, n]) => (
                <button
                  key={c}
                  type="button"
                  className="badge"
                  onClick={() => {
                    setCategory(c)
                    void load(c)
                  }}
                  title={c}
                >
                  {trunc(c, 24)}:{n}
                </button>
              ))}
          </div>
        </Panel>
      </div>

      <Panel
        title="Findings"
        className="flex-1 min-h-0"
        bodyClassName="!p-0 flex flex-col"
        actions={
          <>
            <input
              className="void-input w-52"
              aria-label="Search findings"
              placeholder="Full-text search…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && load()}
            />
            <select
              className="void-input"
              aria-label="Filter findings by category"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
            >
              <option value="">All categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <button type="button" className="void-btn primary" onClick={() => void load()}>
              Search
            </button>
          </>
        }
      >
        {loading ? <div className="p-3"><LoadingState /></div> : null}
        {!loading && error ? (
          <div className="p-3"><ErrorState message={error} onRetry={() => void load()} /></div>
        ) : !loading && findings.length === 0 ? (
          <div className="p-3"><EmptyState message="No findings match filters." /></div>
        ) : (
          <div className="overflow-auto flex-1">
            <table className="void-table">
              <thead>
                <tr>
                  <th>Category</th>
                  <th>Tags</th>
                  <th>Risk</th>
                  <th>Time</th>
                  <th>ID</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr
                    key={String(f.id)}
                    className={selectedId === String(f.id) ? 'selected' : ''}
                    onClick={() => onSelect(f)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        onSelect(f)
                      }
                    }}
                    tabIndex={0}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>{trunc(f.category, 36)}</td>
                    <td className="text-void-text-dim">{(f.tags || []).slice(0, 3).join(', ') || '—'}</td>
                    <td className="mono">{f.risk_score ?? '—'}</td>
                    <td className="mono text-void-text-dim">{f.timestamp || '—'}</td>
                    <td className="mono text-void-text-mute">{trunc(f.id, 14)}</td>
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
