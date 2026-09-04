import { NAV_ITEMS, useUiStore, type ViewId } from '../../store/ui'

export function NavRail() {
  const view = useUiStore((s) => s.view)
  const setView = useUiStore((s) => s.setView)

  return (
    <nav
      className="shrink-0 border-r border-void-line bg-void-panel flex flex-col py-2"
      style={{ width: 232 }}
    >
      <div className="px-3 pb-2 text-[10px] uppercase tracking-wider text-void-text-mute">
        Navigation
      </div>
      {NAV_ITEMS.map((item) => {
        const active = view === item.id
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => setView(item.id as ViewId)}
            className={`mx-2 mb-0.5 flex items-center gap-2 px-2 py-1.5 rounded text-left text-[12px] border ${
              active
                ? 'bg-void-elevated border-void-line text-void-text'
                : 'border-transparent text-void-text-dim hover:bg-void-elevated hover:text-void-text'
            }`}
          >
            <span
              className="w-7 text-[10px] font-mono text-void-text-mute"
              style={{ letterSpacing: '0.02em' }}
            >
              {item.short}
            </span>
            <span>{item.label}</span>
          </button>
        )
      })}
      <div className="mt-auto px-3 pt-3 border-t border-void-line text-[10px] text-void-text-mute">
        localhost:7070 · single-op
      </div>
    </nav>
  )
}
