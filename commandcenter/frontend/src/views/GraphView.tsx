import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import type { ForceGraphMethods } from 'react-force-graph-2d'
import { api } from '../api/client'
import { Panel, EmptyState, LoadingState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { useEngagementStore } from '../store/engagement'

type GNode = {
  id: string
  host_id?: string
  parent_step_id?: string
  step_type?: string
  technique?: string
  outcome_status?: string
  created_at?: string
  [key: string]: unknown
}

type GLink = { source: string; target: string }

const OUTCOME_COLOR: Record<string, string> = {
  success: '#B0606A',
  failed: '#6B747D',
  attempted: '#B79155',
  planned: '#4A5560',
  pending: '#B79155',
  error: '#B0606A',
  ok: '#6E8E6A',
}

const PULSE_MS = 2600
const OUTCOMES = ['success', 'failed', 'attempted', 'planned']

export function GraphView() {
  const [loading, setLoading] = useState(true)
  const [hostFilter, setHostFilter] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState('')
  const [live, setLive] = useState(false)
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined)
  const [, forceTick] = useState(0)
  const openInspector = useUiStore((s) => s.openInspector)
  const setSelectedId = useUiStore((s) => s.setSelectedId)

  const storeGraph = useEngagementStore((s) => s.attackGraph)
  const pulseIds = useEngagementStore((s) => s.pulseIds)
  const lastNodeEvent = useEngagementStore((s) => s.lastNodeEvent)
  const applyAttackGraphFull = useEngagementStore((s) => s.applyAttackGraphFull)

  const load = useCallback(
    (hostId?: string) => {
      setLoading(true)
      api
        .attackGraph(hostId || undefined)
        .then((g) => applyAttackGraphFull(g))
        .catch(() =>
          applyAttackGraphFull({ nodes: [], edges: [], outcomes: [] }),
        )
        .finally(() => setLoading(false))
    },
    [applyAttackGraphFull],
  )

  useEffect(() => {
    load()
  }, [load])

  // Re-paint while any node is pulsing so the ring animates + decays.
  useEffect(() => {
    if (!lastNodeEvent) return
    const until = lastNodeEvent + PULSE_MS + 200
    const timer = setInterval(() => {
      forceTick((t) => t + 1)
      if (Date.now() > until) clearInterval(timer)
    }, 90)
    return () => clearInterval(timer)
  }, [lastNodeEvent])

  // Auto-fit when brand-new nodes arrive.
  const prevCount = useRef(0)
  useEffect(() => {
    const count = storeGraph?.nodes?.length ?? 0
    if (count > prevCount.current && fgRef.current) {
      fgRef.current.zoomToFit(450, 50)
    }
    prevCount.current = count
  }, [storeGraph])

  // Flip to "live" the first time WS delivers the graph.
  useEffect(() => {
    if (storeGraph && !loading) setLive(true)
  }, [storeGraph, loading])

  const data = useMemo(() => {
    const nodes = (storeGraph?.nodes || []) as GNode[]
    let filtered = nodes
    if (outcomeFilter) {
      filtered = nodes.filter(
        (n) => String(n.outcome_status || '').toLowerCase() === outcomeFilter.toLowerCase(),
      )
    }
    if (hostFilter) {
      filtered = filtered.filter((n) => String(n.host_id || '') === hostFilter)
    }
    const ids = new Set(filtered.map((n) => String(n.id)))
    const links: GLink[] = (storeGraph?.edges || [])
      .filter((e) => ids.has(String(e.from)) && ids.has(String(e.to)))
      .map((e) => ({ source: String(e.from), target: String(e.to) }))
    return {
      nodes: filtered.map((n) => ({ ...n, id: String(n.id) })),
      links,
    }
  }, [storeGraph, outcomeFilter, hostFilter])

  const paintNode = useCallback(
    (node: object, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as GNode & { x?: number; y?: number }
      const x = n.x ?? 0
      const y = n.y ?? 0
      const r = 5
      const color = OUTCOME_COLOR[String(n.outcome_status || '').toLowerCase()] || '#6F89A3'
      const pulseStart = pulseIds[String(n.id)]

      // Pulsing ring for recently arrived nodes.
      if (pulseStart) {
        const age = Date.now() - pulseStart
        if (age >= 0 && age < PULSE_MS) {
          const t = age / PULSE_MS // 0 → 1
          const ringR = r + 4 + t * 14
          const alpha = (1 - t) * 0.75
          ctx.beginPath()
          ctx.arc(x, y, ringR, 0, 2 * Math.PI)
          ctx.strokeStyle = `rgba(176, 96, 106, ${alpha})`
          ctx.lineWidth = Math.max(1.2 / globalScale, 0.6)
          ctx.stroke()
        }
      }

      ctx.fillStyle = color
      ctx.beginPath()
      ctx.arc(x, y, r, 0, 2 * Math.PI)
      ctx.fill()

      if (globalScale > 1.2) {
        ctx.font = `${10 / globalScale}px sans-serif`
        ctx.fillStyle = '#8A929B'
        ctx.fillText(String(n.technique || n.step_type || n.id).slice(0, 14), x + 8, y + 3)
      }
    },
    [pulseIds],
  )

  const onNodeClick = useCallback(
    (node: object) => {
      const n = node as GNode
      setSelectedId(String(n.id))
      openInspector({
        title: String(n.technique || n.step_type || n.id),
        subtitle: String(n.id),
        fields: [
          { label: 'Step type', value: n.step_type as string },
          { label: 'Technique', value: n.technique as string },
          { label: 'Outcome', value: n.outcome_status as string },
          { label: 'Host', value: n.host_id as string },
          { label: 'Parent step', value: n.parent_step_id as string },
          { label: 'Created', value: n.created_at as string },
        ],
        json: n,
      })
    },
    [openInspector, setSelectedId],
  )

  return (
    <Panel
      title="Attack Graph"
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
          <input
            className="void-input w-40"
            placeholder="Host ID filter"
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
          />
          <select
            className="void-input"
            value={outcomeFilter}
            onChange={(e) => setOutcomeFilter(e.target.value)}
          >
            <option value="">All outcomes</option>
            {OUTCOMES.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="void-btn primary"
            onClick={() => load(hostFilter)}
          >
            Reload
          </button>
          <button
            type="button"
            className="void-btn"
            onClick={() => fgRef.current?.zoomToFit(400, 40)}
          >
            Fit
          </button>
        </>
      }
    >
      {loading ? (
        <div className="p-3">
          <LoadingState />
        </div>
      ) : null}
      {!loading && data.nodes.length === 0 ? (
        <div className="p-3">
          <EmptyState message="No attack path nodes yet. Nodes appear live as the agent records attack-path steps." />
        </div>
      ) : (
        <div className="flex-1 min-h-[420px] bg-void-bg">
          <ForceGraph2D
            ref={fgRef}
            graphData={data}
            nodeId="id"
            linkSource="source"
            linkTarget="target"
            backgroundColor="#14171A"
            linkColor={() => '#2B3137'}
            nodeCanvasObject={paintNode}
            onNodeClick={onNodeClick}
            cooldownTicks={80}
            linkDirectionalArrowLength={3}
            linkDirectionalArrowRelPos={1}
          />
        </div>
      )}
      <div className="px-3 py-2 border-t border-void-line text-[10px] text-void-text-mute flex gap-4">
        <span>nodes: {data.nodes.length}</span>
        <span>edges: {data.links.length}</span>
        <span>outcomes: {storeGraph?.outcomes?.length ?? 0}</span>
        {storeGraph?.error ? (
          <span className="text-void-error">{storeGraph.error}</span>
        ) : null}
      </div>
    </Panel>
  )
}
