import { useUiStore } from '../../store/ui'

export function Inspector() {
  const open = useUiStore((s) => s.inspectorOpen)
  const inspector = useUiStore((s) => s.inspector)
  const closeInspector = useUiStore((s) => s.closeInspector)

  if (!open || !inspector) return null

  return (
    <aside
      aria-label="Selection inspector"
      className="inspector-panel border-l border-void-line bg-void-panel flex flex-col"
    >
      <div className="flex items-center justify-between px-3 py-2 border-b border-void-line">
        <span className="text-[11px] uppercase tracking-wider text-void-text-dim">Inspector</span>
        <button
          type="button"
          aria-label="Close inspector"
          className="void-btn text-[11px] py-0.5"
          onClick={closeInspector}
        >
          Close
        </button>
      </div>
      <div className="flex-1 overflow-auto p-3">
        <div className="space-y-3">
            <div>
              <div className="text-[14px] font-semibold text-void-text">{inspector.title}</div>
              {inspector.subtitle ? (
                <div className="text-[11px] text-void-text-dim mt-0.5 mono">{inspector.subtitle}</div>
              ) : null}
            </div>
            {inspector.fields && inspector.fields.length > 0 ? (
              <dl className="space-y-1.5">
                {inspector.fields.map((f) => (
                  <div key={f.label} className="flex gap-2 text-[12px]">
                    <dt className="text-void-text-mute w-24 shrink-0">{f.label}</dt>
                    <dd className="text-void-text mono break-all">
                      {f.value == null || f.value === '' ? '—' : String(f.value)}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : null}
            {inspector.json != null ? (
              <pre className="text-[11px] mono bg-void-bg border border-void-line rounded p-2 overflow-auto max-h-80 text-void-text-dim">
                {JSON.stringify(inspector.json, null, 2)}
              </pre>
            ) : null}
            {inspector.actions?.length ? (
              <div className="flex flex-wrap gap-2">
                {inspector.actions.map((a) => (
                  <button key={a.label} type="button" className="void-btn" onClick={a.onClick}>
                    {a.label}
                  </button>
                ))}
              </div>
            ) : null}
        </div>
      </div>
    </aside>
  )
}
