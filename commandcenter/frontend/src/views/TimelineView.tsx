import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api/client'
import { Panel, EmptyState, ErrorState, LoadingState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { useEngagementStore } from '../store/engagement'
import { useWsStore } from '../store/websocket'

type Step = {
  id: string
  host_id?: string
  host_name?: string
  parent_step_id?: string
  step_type?: string
  technique?: string
  outcome_status?: string
  created_at?: string
  epoch: number
}

// Canonical kill-chain ordering for the lane header.
const KILL_CHAIN: Array<{ id: string; label: string; short: string }> = [
  { id: 'initial_access', label: 'Initial Access', short: 'IA' },
  { id: 'privesc', label: 'Privilege Escalation', short: 'PE' },
  { id: 'lateral', label: 'Lateral Movement', short: 'LM' },
  { id: 'persist', label: 'Persistence', short: 'PS' },
  { id: 'exfil', label: 'Exfiltration', short: 'EX' },
  { id: 'c2', label: 'Command & Control', short: 'C2' },
]

const OUTCOME_COLOR: Record<string, string> = {
  success: '#B0606A',
  attempted: '#B79155',
  failed: '#6B747D',
  planned: '#4A5560',
}

const OUTCOME_LABEL: Record<string, string> = {
  success: 'success',
  attempted: 'attempted',
  failed: 'failed',
  planned: 'planned',
}

function toEpoch(created_at?: string): number {
  if (!created_at) return 0
  const ms = new Date(created_at).getTime()
  return Number.isNaN(ms) ? 0 : ms / 1000
}

export function TimelineView() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hostFilter, setHostFilter] = useState('')
  const [t, setT] = useState<number | null>(null) // playhead epoch
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const raf = useRef<number | null>(null)
  const openInspector = useUiStore((s) => s.openInspector)
  const setSelectedId = useUiStore((s) => s.setSelectedId)

  const storeGraph = useEngagementStore((s) => s.attackGraph)
  const pulseIds = useEngagementStore((s) => s.pulseIds)
  const lastNodeEvent = useEngagementStore((s) => s.lastNodeEvent)
  const applyAttackGraphFull = useEngagementStore((s) => s.applyAttackGraphFull)
  const live = useWsStore((s) => s.state) === 'connected'

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api
      .attackGraph()
      .then((g) => applyAttackGraphFull(g))
      .catch((reason) => {
        setError(reason instanceof Error ? reason.message : String(reason))
        applyAttackGraphFull({ nodes: [], edges: [], outcomes: [] })
      })
      .finally(() => setLoading(false))
  }, [applyAttackGraphFull])

  useEffect(() => {
    load()
  }, [load])

  // Ordered, filtered steps with computed epoch.
  const steps = useMemo<Step[]>(() => {
    const raw = (storeGraph?.nodes || []) as Array<Record<string, unknown>>
    const outcomeByNode = new Map<string, string>()
    for (const outcome of (storeGraph?.outcomes || []) as Array<Record<string, unknown>>) {
      const id = String(outcome.attack_path_id || '')
      if (!id || !Object.hasOwn(outcome, 'success')) continue
      if (outcome.success === true || outcome.success === 1) outcomeByNode.set(id, 'success')
      else if (!outcomeByNode.has(id)) outcomeByNode.set(id, 'failed')
    }
    const list: Step[] = raw
      .map((n) => ({
        id: String(n.id ?? ''),
        host_id: n.host_id as string | undefined,
        host_name: n.host_name as string | undefined,
        parent_step_id: n.parent_step_id as string | undefined,
        step_type: n.step_type as string | undefined,
        technique: n.technique as string | undefined,
        outcome_status:
          outcomeByNode.get(String(n.id ?? '')) || (n.outcome_status as string | undefined),
        created_at: n.created_at as string | undefined,
        epoch: toEpoch(n.created_at as string | undefined),
      }))
      .filter((s) => s.id)
    const filtered = hostFilter ? list.filter((s) => s.host_id === hostFilter) : list
    return filtered.sort((a, b) => a.epoch - b.epoch || a.id.localeCompare(b.id))
  }, [storeGraph, hostFilter])

  const hostOptions = useMemo(() => {
    const hosts = new Map<string, string>()
    for (const node of (storeGraph?.nodes || []) as Array<Record<string, unknown>>) {
      const id = String(node.host_id || '')
      if (id) hosts.set(id, String(node.host_name || id))
    }
    return [...hosts.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [storeGraph])

  // Time window.
  const win = useMemo(() => {
    if (steps.length === 0) return { min: 0, max: 1 }
    const min = steps[0].epoch
    const max = steps[steps.length - 1].epoch
    const pad = max - min < 1 ? 1 : (max - min) * 0.03
    return { min: min - pad, max: max + pad }
  }, [steps])

  // Open on the complete evidence trail. Playback explicitly rewinds first,
  // which is less confusing than making an existing engagement look empty.
  useEffect(() => {
    if (steps.length === 0) {
      setT(null)
      setPlaying(false)
      return
    }
    setT((prev) => (prev == null ? win.max : Math.min(Math.max(prev, win.min), win.max)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [win.min, win.max, steps.length])

  // Playback loop.
  useEffect(() => {
    if (!playing) {
      if (raf.current) cancelAnimationFrame(raf.current)
      raf.current = null
      return
    }
    let last = performance.now()
    const tick = (now: number) => {
      const dt = (now - last) / 1000
      last = now
      setT((prev) => {
        if (prev == null) return win.min
        const next = prev + dt * ((win.max - win.min) / 12) * speed
        if (next >= win.max) {
          setPlaying(false)
          return win.max
        }
        return next
      })
      raf.current = requestAnimationFrame(tick)
    }
    raf.current = requestAnimationFrame(tick)
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current)
      raf.current = null
    }
  }, [playing, speed, win.min, win.max])

  const playheadPct = t == null ? 0 : ((t - win.min) / (win.max - win.min)) * 100

  const pctFor = (epoch: number) => ((epoch - win.min) / (win.max - win.min)) * 100

  const revealed = (s: Step) => t != null && s.epoch <= t

  const onStepClick = useCallback(
    (s: Step) => {
      setSelectedId(s.id)
      openInspector({
        title: String(s.technique || s.step_type || s.id),
        subtitle: s.id,
        fields: [
          { label: 'Phase', value: s.step_type },
          { label: 'Technique', value: s.technique },
          { label: 'Outcome', value: s.outcome_status },
          { label: 'Host', value: s.host_name || s.host_id },
          { label: 'Host ID', value: s.host_id },
          { label: 'Parent step', value: s.parent_step_id },
          { label: 'At', value: s.created_at },
        ],
        json: s,
      })
    },
    [openInspector, setSelectedId],
  )

  // Per-phase aggregation for the lane header.
  const phaseAgg = useMemo(() => {
    const map: Record<string, { count: number; revealed: number; outcome: string }> = {}
    for (const s of steps) {
      const key = s.step_type || 'unknown'
      if (!map[key]) map[key] = { count: 0, revealed: 0, outcome: '' }
      map[key].count += 1
      if (revealed(s)) map[key].revealed += 1
      const o = s.outcome_status || ''
      // Keep the "hottest" outcome seen.
      const rank = (x: string) =>
        x === 'success' ? 3 : x === 'attempted' ? 2 : x === 'failed' ? 1 : 0
      if (rank(o) > rank(map[key].outcome)) map[key].outcome = o
    }
    return map
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [steps, t])

  const pulsing = new Set(
    Object.entries(pulseIds || {})
      .filter(([, ts]) => Date.now() - Number(ts) < 2600)
      .map(([id]) => id),
  )

  return (
    <Panel
      title="Engagement Timeline"
      className="h-full"
      bodyClassName="!p-0 flex flex-col"
      actions={
        <>
          <span
            className={
              'text-[10px] px-2 py-1 rounded border ' +
              (live
                ? 'border-void-success/40 text-void-success'
                : 'border-void-line text-void-text-mute')
            }
          >
            {live ? 'LIVE' : 'snapshot'}
          </span>
          <select
            className="void-input max-w-52"
            aria-label="Filter timeline by host"
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
          >
            <option value="">All hosts</option>
            {hostOptions.map(([id, name]) => (
              <option key={id} value={id}>{name}</option>
            ))}
          </select>
          <button type="button" className="void-btn primary" onClick={load}>
            Reload
          </button>
        </>
      }
    >
      {loading ? (
        <div className="p-3">
          <LoadingState />
        </div>
      ) : error ? (
        <div className="p-3">
          <ErrorState message={error} onRetry={load} />
        </div>
      ) : steps.length === 0 ? (
        <div className="p-3">
          <EmptyState message="No attack-path steps yet. The kill-chain timeline fills in live as the agent records engagement phases." />
        </div>
      ) : (
        <div className="flex-1 min-h-0 flex flex-col gap-3 p-3 overflow-auto">
          {/* Kill-chain lane header */}
          <div className="timeline-wide grid gap-1" style={{ gridTemplateColumns: `repeat(${KILL_CHAIN.length}, minmax(0,1fr))` }}>
            {KILL_CHAIN.map((ph) => {
              const agg = phaseAgg[ph.id]
              const active = (agg?.count || 0) > 0
              const color = OUTCOME_COLOR[agg?.outcome || ''] || '#6F89A3'
              return (
                <div
                  key={ph.id}
                  className="rounded border px-2 py-1.5 flex flex-col gap-0.5"
                  style={{
                    borderColor: active ? color : 'var(--color-void-line)',
                    background: active
                      ? `color-mix(in srgb, ${color} 14%, var(--color-void-panel))`
                      : 'var(--color-void-panel)',
                    opacity: active ? 1 : 0.55,
                  }}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-medium text-void-text">{ph.label}</span>
                    <span className="text-[10px] mono" style={{ color: active ? color : 'var(--color-void-text-mute)' }}>
                      {agg ? `${agg.revealed}/${agg.count}` : '0/0'}
                    </span>
                  </div>
                  <div className="text-[9px] uppercase tracking-wider text-void-text-mute">
                    {agg?.outcome ? OUTCOME_LABEL[agg.outcome] || agg.outcome : '—'}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Playback controls */}
          <div className="timeline-wide flex flex-wrap items-center gap-2">
            <button
              type="button"
              className="void-btn primary"
              onClick={() => {
                if (t != null && t >= win.max - 0.001) setT(win.min)
                setPlaying((p) => !p)
              }}
            >
              {playing ? 'Pause' : t != null && t >= win.max - 0.001 ? 'Replay' : 'Play'}
            </button>
            <button
              type="button"
              className="void-btn"
              onClick={() => {
                setPlaying(false)
                setT(win.min)
              }}
            >
              ⏮ Start
            </button>
            <button
              type="button"
              className="void-btn"
              onClick={() => {
                setPlaying(false)
                setT(win.max)
              }}
            >
              End ⏭
            </button>
            <select aria-label="Timeline playback speed" className="void-input w-20" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
              <option value={0.5}>0.5×</option>
              <option value={1}>1×</option>
              <option value={2}>2×</option>
              <option value={4}>4×</option>
            </select>
            <span className="text-[10px] text-void-text-mute mono">
              {steps.filter(revealed).length}/{steps.length} steps · playhead {playheadPct.toFixed(0)}%
            </span>
          </div>

          {/* Timeline strip */}
          <div className="timeline-wide relative flex-1 min-h-[180px] rounded border border-void-line bg-void-bg overflow-hidden">
            {/* axis */}
            <div className="absolute left-3 right-3 bottom-6 top-3">
              {/* playhead */}
              <div
                className="absolute top-0 bottom-0 w-px bg-void-info"
                style={{ left: `${playheadPct}%` }}
              />
              {/* step markers */}
              {steps.map((s) => {
                const rev = revealed(s)
                const color = OUTCOME_COLOR[s.outcome_status || ''] || '#6F89A3'
                const pct = pctFor(s.epoch)
                const isPulse = pulsing.has(s.id)
                return (
                  <button
                    key={s.id}
                    type="button"
                    title={`${s.host_name || s.host_id || 'unknown host'} · ${s.step_type || '?'} · ${s.technique || ''} · ${s.outcome_status || ''}`}
                    onClick={() => onStepClick(s)}
                    className="absolute -translate-x-1/2 bottom-0 flex flex-col items-center focus:outline-none"
                    style={{ left: `${pct}%` }}
                  >
                    <span
                      className="block rounded-full transition-all duration-200"
                      style={{
                        width: isPulse ? 14 : 9,
                        height: isPulse ? 14 : 9,
                        background: rev ? color : 'transparent',
                        border: `2px solid ${color}`,
                        opacity: rev ? 1 : 0.35,
                        boxShadow: isPulse ? `0 0 10px ${color}` : 'none',
                      }}
                    />
                    <span
                      className="mt-1 text-[9px] mono max-w-[70px] truncate"
                      style={{ color: rev ? 'var(--color-void-text)' : 'var(--color-void-text-mute)' }}
                    >
                      {s.step_type || '?'}
                    </span>
                  </button>
                )
              })}
            </div>
            {/* baseline */}
            <div className="absolute left-3 right-3 bottom-[26px] h-px bg-void-line" />
          </div>

          {/* Scrubber */}
          <input
            type="range"
            aria-label="Timeline playhead"
            min={0}
            max={1000}
            value={Math.round(playheadPct * 10)}
            onChange={(e) => {
              setPlaying(false)
              const f = Number(e.target.value) / 1000
              setT(win.min + f * (win.max - win.min))
            }}
            className="timeline-wide w-full accent-[#6F89A3]"
          />
        </div>
      )}
      <div className="px-3 py-2 border-t border-void-line text-[10px] text-void-text-mute flex gap-4">
        <span>steps: {steps.length}</span>
        <span>outcomes: {storeGraph?.outcomes?.length ?? 0}</span>
        {lastNodeEvent ? <span className="text-void-info">last event: {new Date(lastNodeEvent).toLocaleTimeString()}</span> : null}
        {storeGraph?.error ? <span className="text-void-error">{storeGraph.error}</span> : null}
      </div>
    </Panel>
  )
}
