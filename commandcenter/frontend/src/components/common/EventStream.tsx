import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { WarLogEntry } from '../../api/client'
import { levelClass, fmtTs, trunc } from '../../utils/format'
import { useUiStore } from '../../store/ui'

/** Map a warlog level → a severity class used for row accents. */
function sevClass(level?: string): string {
  const l = (level || '').toLowerCase()
  if (l === 'critical') return 'sev-critical'
  if (['error', 'exploit', 'exfil'].includes(l)) return 'sev-error'
  if (['warning', 'stealth'].includes(l)) return 'sev-warning'
  if (['info', 'recon', 'c2'].includes(l)) return 'sev-info'
  if (['agent', 'success', 'ok'].includes(l)) return 'sev-success'
  return 'sev-neutral'
}

const PIN_THRESHOLD = 24 // px from top considered "pinned to latest"

interface EventStreamProps {
  entries: WarLogEntry[]
  live?: boolean
  maxRows?: number
  emptyMessage?: string
}

/**
 * Shared live event stream used by the Dashboard (and any future ops surface).
 * - Severity left-rail coloring + hot-row tint.
 * - Pinned auto-scroll to latest; pauses when the user scrolls down, with a
 *   "Jump to latest" pill. Re-pins automatically near the top.
 * - Click-to-inspect opens the side inspector with full fields + raw JSON.
 * - Fresh-arrival flash on the newest row while live.
 */
export function EventStream({
  entries,
  live = false,
  maxRows = 100,
  emptyMessage = 'No warlog events yet.',
}: EventStreamProps) {
  const openInspector = useUiStore((s) => s.openInspector)
  const setSelectedId = useUiStore((s) => s.setSelectedId)
  const selectedId = useUiStore((s) => s.selectedId)
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const [pinned, setPinned] = useState(true)
  const [freshKey, setFreshKey] = useState<string | null>(null)

  const rows = useMemo(() => entries.slice(0, maxRows), [entries, maxRows])

  const newestKey = rows.length
    ? String(rows[0].id ?? rows[0].epoch ?? '0')
    : null

  // Flash the newest row when it arrives while live.
  useEffect(() => {
    if (!live || !newestKey) return
    setFreshKey(newestKey)
    const t = setTimeout(() => setFreshKey(null), 1500)
    return () => clearTimeout(t)
  }, [live, newestKey])

  // Keep pinned to top unless the user has scrolled away.
  useEffect(() => {
    const el = scrollRef.current
    if (el && pinned) el.scrollTop = 0
  }, [rows.length, pinned])

  const onScroll = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    setPinned(el.scrollTop <= PIN_THRESHOLD)
  }, [])

  const jumpToLatest = useCallback(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = 0
    setPinned(true)
  }, [])

  const onSelect = useCallback(
    (e: WarLogEntry) => {
      const id = String(e.id ?? e.span_id ?? e.epoch)
      setSelectedId(id)
      openInspector({
        title: e.message || e.event_type || 'event',
        subtitle: e.timestamp || String(e.epoch ?? ''),
        fields: [
          { label: 'Level', value: e.level },
          { label: 'Module', value: e.module },
          { label: 'Target', value: e.target },
          { label: 'Type', value: e.event_type },
          { label: 'Trace', value: e.trace_id },
          { label: 'Span', value: e.span_id },
        ],
        json: e,
      })
    },
    [openInspector, setSelectedId],
  )

  if (rows.length === 0) {
    return (
      <div className="p-3 text-void-text-mute text-[12px] border border-dashed border-void-line rounded m-3 text-center">
        {emptyMessage}
      </div>
    )
  }

  return (
    <div className="relative h-full min-h-0">
      <div ref={scrollRef} onScroll={onScroll} className="h-full overflow-auto">
        <table className="void-table event-stream">
          <thead>
            <tr>
              <th>Time</th>
              <th>Level</th>
              <th>Module</th>
              <th>Target</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e, i) => {
              const key = String(e.id ?? e.epoch ?? i)
              const sev = sevClass(e.level)
              const isFresh = live && key === freshKey
              const isSel = key === selectedId
              return (
                <tr
                  key={key}
                  onClick={() => onSelect(e)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      onSelect(e)
                    }
                  }}
                  tabIndex={0}
                  className={[sev, isFresh ? 'fresh' : '', isSel ? 'selected' : '']
                    .filter(Boolean)
                    .join(' ')}
                >
                  <td className="mono text-void-text-dim whitespace-nowrap">
                    {e.timestamp ? fmtTs(e.timestamp) : e.epoch != null ? fmtTsEpoch(e.epoch) : '—'}
                  </td>
                  <td>
                    <span className={`badge ${levelClass(e.level)}`}>{e.level || '—'}</span>
                  </td>
                  <td className="text-void-text-dim whitespace-nowrap">{e.module || '—'}</td>
                  <td className="mono text-void-text-mute whitespace-nowrap">{trunc(e.target, 18)}</td>
                  <td title={e.message}>{trunc(e.message, 90)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Jump-to-latest pill when the user has scrolled away. */}
      {!pinned ? (
        <button
          type="button"
          onClick={jumpToLatest}
          className="absolute bottom-3 left-1/2 -translate-x-1/2 text-[11px] px-3 py-1 rounded-full border border-void-info bg-void-elevated text-void-info shadow"
        >
          ↓ Jump to latest
        </button>
      ) : null}
    </div>
  )
}

function fmtTsEpoch(epoch: number): string {
  try {
    return new Date(epoch * 1000).toISOString().replace('T', ' ').slice(0, 19)
  } catch {
    return String(epoch)
  }
}
