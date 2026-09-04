import { Panel } from '../components/common/Panel'
import { useEngagementStore } from '../store/engagement'
import { useWsStore } from '../store/websocket'

export function SettingsView() {
  const status = useEngagementStore((s) => s.status)
  const ws = useWsStore((s) => s.state)
  const latency = useEngagementStore((s) => s.latencyMs)

  return (
    <div className="max-w-2xl space-y-3">
      <Panel title="Command Center">
        <dl className="space-y-2 text-[12px]">
          <div className="flex gap-3">
            <dt className="w-36 text-void-text-mute">Binding</dt>
            <dd className="mono">127.0.0.1:7070</dd>
          </div>
          <div className="flex gap-3">
            <dt className="w-36 text-void-text-mute">Auth model</dt>
            <dd>Single operator · no login (localhost trust)</dd>
          </div>
          <div className="flex gap-3">
            <dt className="w-36 text-void-text-mute">Scope / authz</dt>
            <dd>Required by the client profile</dd>
          </div>
          <div className="flex gap-3">
            <dt className="w-36 text-void-text-mute">WebSocket</dt>
            <dd className="mono">{ws}</dd>
          </div>
          <div className="flex gap-3">
            <dt className="w-36 text-void-text-mute">API latency</dt>
            <dd className="mono">{latency != null ? `${latency}ms` : '—'}</dd>
          </div>
        </dl>
      </Panel>

      <Panel title="Service health">
        <pre className="text-[11px] mono text-void-text-dim overflow-auto">
          {JSON.stringify(
            {
              degraded: status?.degraded || [],
              boneyard_items: status?.boneyard_items,
              warlog_entries: status?.warlog_entries,
              c2_channels: status?.c2_channels,
            },
            null,
            2,
          )}
        </pre>
      </Panel>

      <Panel title="About">
        <p className="text-[12px] text-void-text-dim leading-relaxed">
          THE VOID Command Center is a read-mostly situational awareness console. It does not
          initiate attacks. It monitors WarLog, Boneyard, C2, and ChaosEngine state on the local
          machine for authorized security validation.
        </p>
      </Panel>
    </div>
  )
}
