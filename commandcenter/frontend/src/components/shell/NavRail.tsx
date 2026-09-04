import { NAV_ITEMS, VIEW_PATHS, useUiStore, type ViewId } from '../../store/ui'

export function NavRail() {
  const view = useUiStore((s) => s.view)
  const setView = useUiStore((s) => s.setView)
  const open = useUiStore((s) => s.mobileNavOpen)

  return (
    <nav
      id="primary-navigation"
      aria-label="Primary navigation"
      className={`nav-rail shrink-0 border-r border-void-line bg-void-panel flex flex-col py-2 ${
        open ? 'nav-rail-open' : ''
      }`}
    >
      <div className="px-3 pb-2 text-[10px] uppercase tracking-wider text-void-text-mute">
        Navigation
      </div>
      {NAV_ITEMS.map((item) => {
        const active = view === item.id
        return (
          <a
            key={item.id}
            href={VIEW_PATHS[item.id]}
            aria-current={active ? 'page' : undefined}
            onClick={(event) => {
              if (
                event.button !== 0 ||
                event.metaKey ||
                event.ctrlKey ||
                event.shiftKey ||
                event.altKey
              ) {
                return
              }
              event.preventDefault()
              setView(item.id as ViewId)
              window.setTimeout(() => document.getElementById('main-content')?.focus(), 0)
            }}
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
          </a>
        )
      })}
      <div className="mt-auto px-3 pt-3 border-t border-void-line text-[10px] text-void-text-mute">
        Local console · single operator
      </div>
    </nav>
  )
}
