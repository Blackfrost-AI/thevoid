import type { ReactNode } from 'react'
import { Topbar } from './Topbar'
import { NavRail } from './NavRail'
import { Inspector } from './Inspector'
import { StatusBar } from './StatusBar'

export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="h-full flex flex-col bg-void-bg">
      <Topbar />
      <div className="flex-1 flex min-h-0">
        <NavRail />
        <main className="flex-1 min-w-0 overflow-auto p-3">{children}</main>
        <Inspector />
      </div>
      <StatusBar />
    </div>
  )
}
