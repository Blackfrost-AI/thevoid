import { useUiStore } from '../../store/ui'
import { useEngagementStore } from '../../store/engagement'
import { useWsStore } from '../../store/websocket'
import { useDemoStore } from '../../store/demo'
import { statusClass } from '../../utils/format'

export function Topbar() {
  const setCommandPalette = useUiStore((s) => s.setCommandPalette)
  const status = useEngagementStore((s) => s.status)
  const ws = useWsStore((s) => s.state)
  const demo = useDemoStore((s) => s.active)
  const demoBusy = useDemoStore((s) => s.busy)
  const demoToggle = useDemoStore((s) => s.toggle)

  const engaged = status?.engaged
  const engLabel = engaged ? 'ENGAGED' : 'IDLE'
  const engClass = engaged ? 'error' : 'success'

  return (
    <header
      className="flex items-center gap-3 px-3 border-b border-void-line bg-void-panel shrink-0"
      style={{ height: 44 }}
    >
      <div className="flex items-center gap-2 min-w-[200px]">
        <div
          className="w-5 h-5 rounded flex items-center justify-center text-[10px] font-bold border border-void-line"
          style={{ background: '#23282E', color: '#B0606A' }}
        >
          V
        </div>
        <span className="font-semibold tracking-wide text-[13px]">THE VOID</span>
        <span className="text-void-text-mute text-[11px]">Command Center</span>
      </div>

      <button
        type="button"
        className="flex-1 max-w-md flex items-center gap-2 px-3 py-1.5 rounded border border-void-line bg-void-bg text-void-text-mute text-[12px] hover:border-void-info"
        onClick={() => setCommandPalette(true)}
      >
        <span className="opacity-70">⌕</span>
        <span>Search or jump…</span>
        <kbd className="ml-auto text-[10px] border border-void-line rounded px-1.5 py-0.5 text-void-text-mute">
          ⌘K
        </kbd>
      </button>

      <div className="ml-auto flex items-center gap-2">
        {demo ? (
          <span className="badge demo-mode" title="DEMO MODE — synthetic stage data">
            DEMO
          </span>
        ) : null}
        <button
          type="button"
          onClick={() => void demoToggle()}
          disabled={demoBusy}
          title={
            demo
              ? 'DEMO MODE active — click to restore live stores'
              : 'Enable DEMO MODE — load the seeded stage scenario'
          }
          className={`demo-toggle ${demo ? 'demo-toggle-on' : ''}`}
        >
          <span className="demo-toggle-dot" />
          {demoBusy ? '…' : demo ? 'DEMO ON' : 'DEMO OFF'}
        </button>
        <span className={`badge ${statusClass(ws === 'connected' ? 'live' : 'degraded')}`}>
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{
              background:
                ws === 'connected' ? 'var(--color-void-success)' : 'var(--color-void-warning)',
            }}
          />
          {ws === 'connected' ? 'LIVE' : ws.toUpperCase()}
        </span>
        <span className={`badge ${engClass}`}>{engLabel}</span>
        {status?.stealth_active ? <span className="badge info">STEALTH</span> : null}
      </div>
    </header>
  )
}
