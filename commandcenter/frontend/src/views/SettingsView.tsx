import { useEffect, useState } from 'react'
import { api, type HealthResponse } from '../api/client'
import { Panel } from '../components/common/Panel'
import { useEngagementStore } from '../store/engagement'
import { useWsStore } from '../store/websocket'

export function SettingsView() {
  const status = useEngagementStore((s) => s.status)
  const ws = useWsStore((s) => s.state)
  const latency = useEngagementStore((s) => s.latencyMs)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthError, setHealthError] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    api.health()
      .then((value) => {
        if (active) setHealth(value)
      })
      .catch((error: unknown) => {
        if (active) setHealthError(error instanceof Error ? error.message : String(error))
      })
    return () => {
      active = false
    }
  }, [])

  return (
    <div className="max-w-2xl space-y-3">
      <Panel title="Command Center">
        <dl className="space-y-2 text-[12px]">
          <div className="flex gap-3">
            <dt className="w-36 text-void-text-mute">Binding</dt>
            <dd className="mono">{health ? `${health.host}:${health.port}` : 'localhost'}</dd>
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

      <Panel title="Commercial entitlement">
        {health?.license ? (
          <dl className="space-y-2 text-[12px]">
            <div className="flex gap-3">
              <dt className="w-36 text-void-text-mute">Status</dt>
              <dd className={health.license.permitted ? 'text-emerald-400' : 'text-red-400'}>
                {health.license.state}
              </dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-36 text-void-text-mute">Customer</dt>
              <dd className="mono">{health.license.customer_id || '—'}</dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-36 text-void-text-mute">License</dt>
              <dd className="mono">{health.license.license_id || '—'}</dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-36 text-void-text-mute">Expires</dt>
              <dd className="mono">{health.license.expires_at || 'never'}</dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-36 text-void-text-mute">Features</dt>
              <dd>{health.license.features.join(', ') || '—'}</dd>
            </div>
            <p className="pt-1 text-void-text-dim">{health.license.message}</p>
          </dl>
        ) : (
          <p className="text-[12px] text-void-text-dim">
            {healthError ? `Unable to read entitlement: ${healthError}` : 'Checking entitlement…'}
          </p>
        )}
      </Panel>

      <Panel title="Service health">
        <pre className="text-[11px] mono text-void-text-dim overflow-auto">
          {JSON.stringify(
            {
              degraded: status?.degraded || [],
              boneyard_items: status?.boneyard_items,
              warlog_entries: status?.warlog_entries,
              c2_channels: status?.c2_channels,
              c2_active_channels: status?.c2_active_channels,
              c2_recorded_channels: status?.c2_recorded_channels,
            },
            null,
            2,
          )}
        </pre>
      </Panel>

      <Panel title="About">
        <p className="text-[12px] text-void-text-dim leading-relaxed">
          THE VOID Command Center is a visual-first evidence and situational-awareness console.
          It monitors persisted engagements, WarLog, Boneyard, C2 evidence, and reports on this
          machine. Validation-job launch and approval controls are not part of this release.
        </p>
      </Panel>
    </div>
  )
}
