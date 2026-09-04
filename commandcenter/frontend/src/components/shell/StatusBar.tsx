import { useEngagementStore } from '../../store/engagement'
import { useWsStore } from '../../store/websocket'

export function StatusBar() {
  const status = useEngagementStore((s) => s.status)
  const metrics = useEngagementStore((s) => s.metrics)
  const latency = useEngagementStore((s) => s.latencyMs)
  const ws = useWsStore((s) => s.state)

  const session = metrics?.session_id
  const targetCount = status?.target_count ?? 0
  const warlog = metrics?.warlog_entries ?? status?.warlog_entries ?? 0
  const beacons = metrics?.c2_beacons ?? status?.c2_beacons ?? status?.beacon_count ?? 0
  const channels = metrics?.c2_channels ?? status?.c2_channels ?? 0

  return (
    <footer
      aria-label="Runtime status"
      className="statusbar shrink-0 border-t border-void-line bg-void-panel flex items-center gap-4 px-3 text-[11px] text-void-text-dim mono"
    >
      {session ? (
        <span className="status-hide-mobile">
          session <span className="text-void-text">{String(session).slice(0, 12)}</span>
        </span>
      ) : (
        <span className="status-hide-mobile">
          targets <span className="text-void-text">{targetCount}</span>
        </span>
      )}
      <span className="status-hide-mobile">
        warlog <span className="text-void-text">{warlog}</span>
      </span>
      <span className="status-hide-mobile">
        beacons <span className="text-void-text">{beacons}</span>
      </span>
      <span>
        channels <span className="text-void-text">{channels}</span>
      </span>
      <span>
        ws <span className="text-void-text">{ws}</span>
      </span>
      <span className="ml-auto">
        latency{' '}
        <span className="text-void-text">{latency != null ? `${latency}ms` : '—'}</span>
      </span>
      {status?.degraded?.length ? (
        <span className="badge warning">degraded: {status.degraded.join(', ')}</span>
      ) : null}
    </footer>
  )
}
