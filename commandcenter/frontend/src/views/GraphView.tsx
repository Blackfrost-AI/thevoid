import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import type { ForceGraphMethods } from 'react-force-graph-2d'
import { api } from '../api/client'
import { Panel, EmptyState, ErrorState, LoadingState } from '../components/common/Panel'
import { useUiStore } from '../store/ui'
import { useEngagementStore } from '../store/engagement'
import { useWsStore } from '../store/websocket'

type GNode = {
  id: string
  host_id?: string
  host_name?: string
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

function useElementSize(ref: React.RefObject<HTMLDivElement | null>, refreshKey: unknown) {
  const [size, setSize] = useState({ width: 0, height: 0 })

  useLayoutEffect(() => {
    const element = ref.current
    if (!element) return
    const update = () => {
      const next = {
        width: Math.max(0, Math.floor(element.clientWidth)),
        height: Math.max(0, Math.floor(element.clientHeight)),
      }
      setSize((current) =>
        current.width === next.width && current.height === next.height ? current : next,
      )
    }
    update()
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [ref, refreshKey])

  return size
}

export function GraphView() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hostFilter, setHostFilter] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState('')
  const fgRef = useRef<ForceGraphMethods | undefined>(undefined)
  const graphHostRef = useRef<HTMLDivElement | null>(null)
  // The graph host is mounted only after loading completes. Re-run the
  // measurement effect at that transition so the first production render
  // cannot remain an empty, zero-sized canvas host.
  const graphSize = useElementSize(graphHostRef, loading)
  const [, forceTick] = useState(0)
  const openInspector = useUiStore((s) => s.openInspector)
  const setSelectedId = useUiStore((s) => s.setSelectedId)

  const storeGraph = useEngagementStore((s) => s.attackGraph)
  const pulseIds = useEngagementStore((s) => s.pulseIds)
  const lastNodeEvent = useEngagementStore((s) => s.lastNodeEvent)
  const applyAttackGraphFull = useEngagementStore((s) => s.applyAttackGraphFull)
  const wsState = useWsStore((s) => s.state)
  const live = wsState === 'connected'

  const load = useCallback(
    (hostId?: string) => {
      setLoading(true)
      setError(null)
      api
        .attackGraph(hostId || undefined)
        .then((g) => {
          applyAttackGraphFull(g)
          if (g.error) setError(g.error)
        })
        .catch((reason) => {
          setError(reason instanceof Error ? reason.message : String(reason))
          applyAttackGraphFull({ nodes: [], edges: [], outcomes: [] })
        })
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

  const data = useMemo(() => {
    const outcomes = (storeGraph?.outcomes || []) as Array<Record<string, unknown>>
    const outcomeByNode = new Map<string, string>()
    for (const outcome of outcomes) {
      const id = String(outcome.attack_path_id || '')
      if (!id || !Object.hasOwn(outcome, 'success')) continue
      if (outcome.success === true || outcome.success === 1) outcomeByNode.set(id, 'success')
      else if (!outcomeByNode.has(id)) outcomeByNode.set(id, 'failed')
    }
    const nodes = ((storeGraph?.nodes || []) as GNode[]).map((node) => ({
      ...node,
      outcome_status: outcomeByNode.get(String(node.id)) || node.outcome_status,
    }))
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

  const hostOptions = useMemo(() => {
    const hosts = new Map<string, string>()
    for (const node of (storeGraph?.nodes || []) as GNode[]) {
      if (node.host_id) hosts.set(node.host_id, node.host_name || node.host_id)
    }
    return [...hosts.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [storeGraph])

  // ForceGraph defaults to the browser window size. Pin it to the actual
  // panel and fit after its forces have had a moment to settle.
  useEffect(() => {
    if (!data.nodes.length || graphSize.width === 0 || graphSize.height === 0) return
    const timer = window.setTimeout(() => fgRef.current?.zoomToFit(350, 48), 450)
    return () => window.clearTimeout(timer)
  }, [data.nodes.length, graphSize.width, graphSize.height])

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
        const technique = String(n.technique || n.step_type || n.id)
        const label = n.step_type === 'initial_access' && n.host_name
          ? `${n.host_name} · ${technique}`
          : technique
        ctx.fillText(label.slice(0, 28), x + 8, y + 3)
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
          { label: 'Host', value: n.host_name || (n.host_id as string) },
          { label: 'Host ID', value: n.host_id as string },
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
          <select
            className="void-input max-w-52"
            aria-label="Filter graph by host"
            value={hostFilter}
            onChange={(e) => setHostFilter(e.target.value)}
          >
            <option value="">All hosts</option>
            {hostOptions.map(([id, name]) => (
              <option key={id} value={id}>{name}</option>
            ))}
          </select>
          <select
            className="void-input"
            aria-label="Filter graph by outcome"
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
            onClick={() => load()}
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
      {!loading && error ? (
        <div className="p-3">
          <ErrorState message={error} onRetry={() => load()} />
        </div>
      ) : !loading && data.nodes.length === 0 ? (
        <div className="p-3">
          <EmptyState message="No attack path nodes yet. Nodes appear live as the agent records attack-path steps." />
        </div>
      ) : !loading ? (
        <div
          ref={graphHostRef}
          aria-label={`Interactive attack graph with ${data.nodes.length} nodes and ${data.links.length} edges`}
          className="flex-1 min-h-[320px] bg-void-bg overflow-hidden"
        >
          {graphSize.width > 0 && graphSize.height > 0 ? (
            <ForceGraph2D
              ref={fgRef}
              width={graphSize.width}
              height={graphSize.height}
              graphData={data}
              nodeId="id"
              linkSource="source"
              linkTarget="target"
              backgroundColor="#14171A"
              linkColor={() => '#2B3137'}
              nodeCanvasObject={paintNode}
              onNodeClick={onNodeClick}
              dagMode="lr"
              dagLevelDistance={100}
              cooldownTicks={80}
              onEngineStop={() => fgRef.current?.zoomToFit(400, 60)}
              linkDirectionalArrowLength={3}
              linkDirectionalArrowRelPos={1}
            />
          ) : null}
        </div>
      ) : null}
      <div className="px-3 py-2 border-t border-void-line text-[10px] text-void-text-mute flex flex-wrap gap-4">
        <span>nodes: {data.nodes.length}</span>
        <span>edges: {data.links.length}</span>
        <span>outcomes: {storeGraph?.outcomes?.length ?? 0}</span>
        <span>hosts: {hostOptions.length}</span>
        {['success', 'failed', 'attempted'].map((status) => (
          <span key={status} className="inline-flex items-center gap-1">
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 rounded-full"
              style={{ background: OUTCOME_COLOR[status] }}
            />
            {status}
          </span>
        ))}
        {storeGraph?.error ? (
          <span className="text-void-error">{storeGraph.error}</span>
        ) : null}
      </div>
    </Panel>
  )
}
