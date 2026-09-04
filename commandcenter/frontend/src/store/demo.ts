/** DEMO MODE store — mirrors backend demo status, drives toggle + badges. */

import { create } from 'zustand'
import { api } from '../api/client'
import type { DemoStatus } from '../api/client'
import { useEngagementStore } from './engagement'

interface DemoState {
  active: boolean
  status: DemoStatus | null
  loading: boolean
  error: string | null
  busy: boolean

  /** Fetch current demo status (also used on app boot). */
  refresh: () => Promise<void>
  toggle: () => Promise<void>
  enable: () => Promise<void>
  disable: () => Promise<void>
  /** WS pushes from the backend (demo_state messages). */
  applyDemoState: (data: Record<string, unknown>) => void
}

export const useDemoStore = create<DemoState>((set, get) => ({
  active: false,
  status: null,
  loading: false,
  error: null,
  busy: false,

  refresh: async () => {
    set({ loading: true })
    try {
      const status = await api.demoStatus()
      set({ active: status.demo_mode, status, loading: false, error: null })
      if (status.demo_mode) {
        // Boot-time: if demo was already active, re-fetch live panels so the
        // engagement store sees demo data immediately.
        await useEngagementStore.getState().fetchAttackGraph()
      }
    } catch (e) {
      set({ loading: false, error: String(e) })
    }
  },

  enable: async () => {
    set({ busy: true, error: null })
    try {
      const status = await api.demoEnable()
      set({ active: status.demo_mode, status, busy: false })
      if (status.demo_mode) {
        await useEngagementStore.getState().fetchAttackGraph()
      }
    } catch (e) {
      set({ busy: false, error: String(e) })
    }
  },

  disable: async () => {
    set({ busy: true, error: null })
    try {
      const status = await api.demoDisable()
      set({ active: status.demo_mode, status, busy: false })
      // Clear the live attack graph so stale demo nodes don't linger, then
      // re-fetch status + graph from the restored live stores. The poller
      // will also push a fresh engagement_update shortly.
      useEngagementStore.setState({
        attackGraph: null,
        pulseIds: {},
        lastNodeEvent: null,
      })
      await Promise.all([
        useEngagementStore.getState().fetchStatus(),
        useEngagementStore.getState().fetchAttackGraph(),
      ])
    } catch (e) {
      set({ busy: false, error: String(e) })
    }
  },

  toggle: async () => {
    const { active, busy } = get()
    if (busy) return
    await (active ? get().disable() : get().enable())
  },

  applyDemoState: (data) => {
    const s = data as unknown as DemoStatus
    set({ active: !!s.demo_mode, status: s, busy: false })
  },
}))
