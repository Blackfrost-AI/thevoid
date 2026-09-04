import type { ReactNode } from 'react'
import { Topbar } from './Topbar'
import { NavRail } from './NavRail'
import { Inspector } from './Inspector'
import { StatusBar } from './StatusBar'
import { useUiStore } from '../../store/ui'

export function Shell({ children }: { children: ReactNode }) {
  const mobileNavOpen = useUiStore((s) => s.mobileNavOpen)
  const setMobileNav = useUiStore((s) => s.setMobileNav)

  return (
    <div className="h-full flex flex-col bg-void-bg">
      <a className="skip-link" href="#main-content">
        Skip to workspace
      </a>
      <Topbar />
      <div className="shell-body flex-1 flex min-h-0 relative">
        {mobileNavOpen ? (
          <button
            type="button"
            className="nav-backdrop"
            aria-label="Close navigation"
            onClick={() => setMobileNav(false)}
          />
        ) : null}
        <NavRail />
        <main
          id="main-content"
          aria-label="Command Center workspace"
          className="shell-main flex-1 min-w-0 overflow-auto p-3"
          tabIndex={-1}
        >
          {children}
        </main>
        <Inspector />
      </div>
      <StatusBar />
    </div>
  )
}
