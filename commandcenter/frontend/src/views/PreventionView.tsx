import { useCallback, useEffect, useState } from 'react'
import { Panel, Stat, EmptyState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { api } from '../api/client'
import type { CoverageResponse, EngagementScore } from '../types/insights'

const REFRESH_MS = 30_000

/** Verdict class → tone color, mirroring CLI rubric display. */
const VERDICT_COLOR: Record<string, string> = {
  verified: 'var(--color-void-success)',
  exploited: 'var(--color-void-error)',
  reachability: 'var(--color-void-warning)',
  unknown: 'var(--color-void-neutral)',
}

function scoreTone(score: number): string {
  if (score >= 80) return 'var(--color-void-error)' // strong prevention = red heat
  if (score >= 50) return 'var(--color-void-warning)'
  return 'var(--color-void-success)'
}

function Gauge({ value }: { value: number }) {
  const r = 54
  const c = 2 * Math.PI * r
  const filled = Math.max(0, Math.min(100, value)) / 100
  return (
    <svg width="150" height="150" viewBox="0 0 150 150" role="img" aria-label={`Prevention strength ${value.toFixed(1)}%`}>
      <circle cx="75" cy="75" r={r} fill="none" stroke="var(--color-void-line)" strokeWidth="10" />
      <circle
        cx="75"
        cy="75"
        r={r}
        fill="none"
        stroke={scoreTone(value)}
        strokeWidth="10"
        strokeLinecap="round"
        strokeDasharray={`${c * filled} ${c * (1 - filled)}`}
        transform="rotate(-90 75 75)"
      />
      <text x="75" y="70" textAnchor="middle" fill="var(--color-void-text)" fontSize="24" fontWeight="700" fontFamily="var(--font-mono)">
        {value.toFixed(1)}
      </text>
      <text x="75" y="90" textAnchor="middle" fill="var(--color-void-text-mute)" fontSize="10" letterSpacing="2">
        PREVENTION %
      </text>
    </svg>
  )
}

export function PreventionView() {
  const openInspector = useUiStore((s) => s.openInspector)
  const [data, setData] = useState<CoverageResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      setData(await api.coverage())
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

  const inspectEngagement = (eng: EngagementScore) =>
    openInspector({
      title: `Engagement #${eng.engagement_index} — ${eng.target}`,
      subtitle: `mode: ${eng.mode} · score ${eng.score.toFixed(1)}/100`,
      fields: [
        { label: 'Target', value: eng.target },
        { label: 'Mode', value: eng.mode },
        { label: 'Phases', value: eng.phases.join(' → ') || '—' },
        { label: 'Score', value: eng.score.toFixed(1) },
        {
          label: 'Verdicts',
          value: Object.entries(eng.verdict_counts)
            .map(([k, v]) => `${k}:${v}`)
            .join(' ') || 'none',
        },
      ],
      json: eng,
    })

  const totals: Record<string, number> = {}
  for (const eng of data?.engagement_scores ?? []) {
    for (const [k, v] of Object.entries(eng.verdict_counts)) {
      totals[k] = (totals[k] || 0) + v
    }
  }

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-1 xl:grid-cols-4 gap-3">
        <Panel title="Aggregate Prevention Strength" className="xl:col-span-1">
          <div className="flex items-center justify-center py-2">
            <Gauge value={data?.aggregated ?? 0} />
          </div>
          <div className="text-center text-[11px] text-void-text-mute">
            Mean R-2 score across {data?.count ?? 0} engagement{data?.count === 1 ? '' : 's'}
          </div>
        </Panel>

        <Panel title="Scoring Inputs" className="xl:col-span-3">
          <div className="flex flex-wrap gap-5">
            <Stat label="Aggregated" value={data ? `${data.aggregated.toFixed(1)}%` : '—'} tone="success" />
            <Stat label="Engagements" value={data?.count ?? 0} tone="info" />
            {Object.entries(totals).map(([k, v]) => (
              <Stat key={k} label={k} value={v} />
            ))}
          </div>
          <div className="mt-4 flex flex-wrap gap-3 text-[10px] text-void-text-mute">
            <span>rubric: verified=1.0 · exploited=0.7 · reachability=0.3 · unknown=0.0</span>
          </div>
          {error ? <div className="mt-3 text-[11px] text-void-error">{error}</div> : null}
          <button type="button" className="void-btn mt-3" onClick={load} disabled={busy}>
            {busy ? 'Scoring…' : 'Rescore now'}
          </button>
        </Panel>
      </div>

      <Panel
        title="Per-Engagement Breakdown"
        className="flex-1 min-h-[280px]"
        bodyClassName="!p-0 overflow-auto"
        actions={
          <button type="button" className="void-btn" onClick={load} disabled={busy}>
            Refresh
          </button>
        }
      >
        {!data ? (
          <div className="p-3">{busy ? <EmptyState message="Scoring…" /> : <EmptyState message="Loading…" />}</div>
        ) : data.engagement_scores.length === 0 ? (
          <div className="p-3">
            <EmptyState message="No engagements scored yet — run an engagement to populate the rubric." />
          </div>
        ) : (
          <table className="void-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Target</th>
                <th>Mode</th>
                <th>Phases</th>
                <th>Score</th>
                <th>Verdicts</th>
              </tr>
            </thead>
            <tbody>
              {data.engagement_scores.map((eng) => (
                <tr
                  key={eng.engagement_index}
                  className="cursor-pointer"
                  onClick={() => inspectEngagement(eng)}
                >
                  <td className="mono text-void-text-mute">{eng.engagement_index}</td>
                  <td>{eng.target}</td>
                  <td className="text-void-text-dim">{eng.mode}</td>
                  <td className="text-void-text-dim" title={eng.phases.join(' → ')}>
                    {eng.phases.join(' → ') || '—'}
                  </td>
                  <td>
                    <div className="flex items-center gap-2 min-w-[140px]">
                      <div className="score-bar flex-1">
                        <div
                          className="score-bar-fill"
                          style={{ width: `${eng.score}%`, background: scoreTone(eng.score) }}
                        />
                      </div>
                      <span className="mono text-[11px]" style={{ color: scoreTone(eng.score) }}>
                        {eng.score.toFixed(1)}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="flex gap-1">
                      {Object.entries(eng.verdict_counts).map(([k, v]) => (
                        <span key={k} className="badge" style={{ color: VERDICT_COLOR[k] || undefined }}>
                          {k}:{v}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  )
}
