import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Panel, Stat, EmptyState } from '../components/common/Panel'
import { EventStream } from '../components/common/EventStream'
import { useEngagementStore } from '../store/engagement'
import { useUiStore } from '../store/ui'
import { levelClass, trunc } from '../utils/format'
import { api } from '../api/client'
import type { MitreResponse, MitreTechnique } from '../types/insights'

const REFRESH_MS = 30_000

const PHASE_MAP =
  'color-mix(in srgb, var(--color-void-error) 35%, var(--color-void-panel))'
const FINDING_MAP =
  'color-mix(in srgb, var(--color-void-warning) 30%, var(--color-void-panel))'
const ALIAS_MAP =
  'color-mix(in srgb, var(--color-void-info) 25%, var(--color-void-panel))'

/** Cell tint: ALIAS/UNMAPPED techniques are advisory-blue, phase-mapped are
 *  solid red, finding-mapped are amber. Matches CLI report conventions. */
function cellStyle(tech: MitreTechnique, phaseMapped: Set<string>): string {
  if (tech.id.startsWith('ALIAS:') || tech.id.startsWith('UNMAPPED')) return ALIAS_MAP
  if (phaseMapped.has(tech.id)) return PHASE_MAP
  return FINDING_MAP
}

export function DashboardView() {
  const status = useEngagementStore((s) => s.status)
  const live = useEngagementStore((s) => s.warlogLive)
  const metricsHistory = useEngagementStore((s) => s.metricsHistory)
  const metrics = useEngagementStore((s) => s.metrics)
  const openInspector = useUiStore((s) => s.openInspector)
  const [seedEntries, setSeedEntries] = useState<typeof live>([])
  const [levelCounts, setLevelCounts] = useState<Record<string, number>>({})
  const [mitre, setMitre] = useState<MitreResponse | null>(null)
  const [prevention, setPrevention] = useState<number | null>(null)

  const loadInsights = useCallback(() => {
    api
      .mitre()
      .then(setMitre)
      .catch(() => setMitre(null))
    api
      .coverage()
      .then((c) => setPrevention(typeof c.aggregated === 'number' ? c.aggregated : null))
      .catch(() => setPrevention(null))
  }, [])

  useEffect(() => {
    api.warlogEntries({ limit: '40' }).then((r) => setSeedEntries(r.entries)).catch(() => {})
    api.warlogSummary().then((s) => setLevelCounts(s.level_counts || {})).catch(() => {})
  }, [])

  useEffect(() => {
    loadInsights()
    const t = setInterval(loadInsights, REFRESH_MS)
    return () => clearInterval(t)
  }, [loadInsights])

  const stream = live.length ? live : seedEntries
  const levels = metrics?.level_counts || levelCounts

  const phaseMapped = useMemo(
    () => new Set(Object.values(mitre?.mapped_phases ?? {}).map((t) => t.id)),
    [mitre],
  )

  const heatColumns = useMemo(() => {
    if (!mitre) return []
    return mitre.tactics.map((tactic) => ({
      tactic,
      techs: mitre.techniques_used.filter((t) => t.tactic === tactic),
    }))
  }, [mitre])

  const phasesHit = Object.keys(mitre?.mapped_phases ?? {}).length

  const inspectTechnique = (tech: MitreTechnique) => {
    const count = mitre?.technique_counts?.[tech.id]
    openInspector({
      title: `${tech.id} — ${tech.name}`,
      subtitle: `tactic: ${tech.tactic}`,
      fields: [
        { label: 'Technique ID', value: tech.id },
        { label: 'Tactic', value: tech.tactic },
        { label: 'Mapped occurrences', value: count ?? 0 },
        { label: 'Mapped via phase', value: phaseMapped.has(tech.id) ? 'yes' : 'no' },
      ],
      json: tech,
    })
  }

  const chartData = metricsHistory.map((p) => ({
    t: new Date(p.t * 1000).toLocaleTimeString(),
    rate: p.rate,
  }))

  return (
    <div className="h-full flex flex-col gap-3">
      <div className="grid grid-cols-2 xl:grid-cols-5 gap-3">
        <Panel title="Engagement Status">
          <div className="flex flex-wrap gap-4">
            <Stat
              label="State"
              value={status?.engaged ? 'ENGAGED' : 'IDLE'}
              tone={status?.engaged ? 'error' : 'success'}
            />
            <Stat label="Targets" value={status?.target_count ?? 0} tone="info" />
            <Stat label="Sessions" value={status?.active_sessions?.length ?? 0} />
            <Stat label="Stolen" value={status?.stolen_data ?? 0} tone="warning" />
            <Stat label="Attacks" value={status?.attack_log ?? 0} />
            <Stat
              label="Stealth"
              value={status?.stealth_active ? 'ON' : 'OFF'}
              tone={status?.stealth_active ? 'info' : undefined}
            />
          </div>
        </Panel>

        <Panel title="C2 Health">
          <div className="flex flex-wrap gap-4">
            <Stat label="Channels" value={status?.c2_channels ?? 0} tone="info" />
            <Stat label="Beacons" value={status?.c2_beacons ?? status?.beacon_count ?? 0} />
            <Stat label="Tasks" value={status?.c2_tasks ?? 0} />
            <Stat label="Boneyard" value={status?.boneyard_items ?? 0} tone="success" />
          </div>
        </Panel>

        <Panel title="Insight Engines">
          <div className="flex flex-wrap gap-4">
            <Stat
              label="Prevention"
              value={prevention == null ? '—' : `${prevention.toFixed(1)}%`}
              tone="success"
            />
            <Stat
              label="MITRE Techs"
              value={mitre ? mitre.techniques_used.length : '—'}
              tone="info"
            />
            <Stat label="Tactics Hit" value={mitre ? heatColumns.length : '—'} />
            <Stat label="Phases Mapped" value={mitre ? phasesHit : '—'} />
          </div>
        </Panel>

        <Panel title="WarLog Summary">
          <div className="flex flex-wrap gap-4">
            <Stat label="Entries" value={status?.warlog_entries ?? 0} />
            <Stat label="EPM" value={metrics?.events_per_minute ?? 0} tone="info" />
          </div>
          <div className="mt-3 flex flex-wrap gap-1">
            {Object.entries(levels)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 8)
              .map(([lvl, n]) => (
                <span key={lvl} className={`badge ${levelClass(lvl)}`}>
                  {lvl}:{n}
                </span>
              ))}
          </div>
        </Panel>

        <Panel title="Event Rate">
          {chartData.length < 2 ? (
            <EmptyState message="Waiting for metrics ticks…" />
          ) : (
            <div className="h-24">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <XAxis dataKey="t" hide />
                  <YAxis hide domain={[0, 'auto']} />
                  <Tooltip
                    contentStyle={{
                      background: '#23282E',
                      border: '1px solid #2B3137',
                      fontSize: 11,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="rate"
                    stroke="#6F89A3"
                    fill="#6F89A333"
                    strokeWidth={1.5}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>

      <div className="flex-1 grid grid-cols-1 xl:grid-cols-3 gap-3 min-h-0">
        <Panel
          title="WarLog Event Stream"
          className="xl:col-span-2 min-h-[280px]"
          bodyClassName="!p-0"
          actions={
            <span className="flex items-center gap-1.5 text-[10px] text-void-text-mute">
              <span className="live-dot" style={{ opacity: live.length ? 1 : 0.25 }} />
              {live.length ? 'LIVE' : 'history'}
              <span className="ml-2">{stream.length} events</span>
            </span>
          }
        >
          <EventStream entries={stream} live={live.length > 0} />
        </Panel>

        <Panel
          title="MITRE ATT&CK Coverage"
          actions={
            mitre ? (
              <span className="badge info">
                {mitre.coverage_pct.toFixed(1)}% · {mitre.native_techniques_used}/
                {mitre.coverage_denominator} native
              </span>
            ) : null
          }
          bodyClassName="overflow-auto"
        >
          {mitre == null ? (
            <EmptyState message="No MITRE annotation yet — run an engagement." />
          ) : heatColumns.length === 0 ? (
            <EmptyState message="No techniques mapped. Findings are unmapped — check alias rules." />
          ) : (
            <>
              <div className="mitre-heatmap">
                {heatColumns.map(({ tactic, techs }) => (
                  <div key={tactic} className="mitre-tactic-col">
                    <div className="mitre-tactic-head">
                      <span>{tactic}</span>
                      <span className="mitre-tactic-count">{techs.length}</span>
                    </div>
                    {techs.map((tech) => (
                      <button
                        key={tech.id}
                        type="button"
                        className="mitre-cell"
                        style={{ background: cellStyle(tech, phaseMapped) }}
                        title={`${tech.id} — ${tech.name} (${
                          mitre.technique_counts?.[tech.id] ?? 0
                        } occurrences)`}
                        onClick={() => inspectTechnique(tech)}
                      >
                        <span className="mitre-cell-id">{tech.id}</span>
                        <span className="mitre-cell-name">{trunc(tech.name, 30)}</span>
                      </button>
                    ))}
                  </div>
                ))}
              </div>
              <div className="mt-3 flex flex-wrap gap-3 text-[10px] text-void-text-mute">
                <span>
                  <span
                    className="inline-block w-2 h-2 rounded-sm mr-1"
                    style={{ background: '#B0606A' }}
                  />
                  phase-mapped
                </span>
                <span>
                  <span
                    className="inline-block w-2 h-2 rounded-sm mr-1"
                    style={{ background: '#B79155' }}
                  />
                  finding-mapped
                </span>
                <span>
                  <span
                    className="inline-block w-2 h-2 rounded-sm mr-1"
                    style={{ background: '#6F89A3' }}
                  />
                  alias / unmapped
                </span>
              </div>
              {mitre.alias_techniques_used > 0 ? (
                <div className="mt-2 text-[10px] text-void-text-mute">
                  {mitre.alias_techniques_used} alias technique
                  {mitre.alias_techniques_used === 1 ? '' : 's'} observed
                </div>
              ) : null}
            </>
          )}
        </Panel>
      </div>
    </div>
  )
}
