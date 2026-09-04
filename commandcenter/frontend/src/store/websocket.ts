import { create } from 'zustand'
import { wsUrl } from '../api/client'
import type { Status, WarLogEntry } from '../api/client'
import { useEngagementStore } from './engagement'
import { useDemoStore } from './demo'

type ConnState = 'disconnected' | 'connecting' | 'connected' | 'error'

interface WsState {
  state: ConnState
  lastError: string | null
  connect: () => void
  disconnect: () => void
  send: (msg: unknown) => void
}

let socket: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
let intentionalClose = false
let attempt = 0

function scheduleReconnect(connect: () => void) {
  if (reconnectTimer) return
  const delay = Math.min(1000 * 2 ** attempt, 15000)
  attempt += 1
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null
    connect()
  }, delay)
}

export const useWsStore = create<WsState>((set, get) => ({
  state: 'disconnected',
  lastError: null,

  connect: () => {
    intentionalClose = false
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return
    }
    set({ state: 'connecting', lastError: null })
    try {
      socket = new WebSocket(wsUrl())
    } catch (e) {
      set({ state: 'error', lastError: String(e) })
      scheduleReconnect(() => get().connect())
      return
    }

    socket.onopen = () => {
      attempt = 0
      set({ state: 'connected' })
      socket?.send(
        JSON.stringify({
          type: 'subscribe',
          channels: ['warlog', 'c2', 'engagement', 'metrics', 'integrity', 'attack_graph', 'demo'],
        }),
      )
    }

    socket.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data as string) as { type: string; data: unknown }
        const eng = useEngagementStore.getState()
        switch (msg.type) {
          case 'warlog_entry':
            eng.pushWarlog(msg.data as WarLogEntry)
            break
          case 'engagement_update':
            eng.applyEngagementUpdate(msg.data as Status)
            break
          case 'metrics_tick':
            eng.setMetrics(msg.data as Parameters<typeof eng.setMetrics>[0])
            break
          case 'attack_node':
            eng.applyAttackNode(msg.data as Record<string, unknown>)
            break
          case 'attack_graph_full':
            eng.applyAttackGraphFull(
              msg.data as Parameters<typeof eng.applyAttackGraphFull>[0],
            )
            break
          case 'demo_state':
            useDemoStore.getState().applyDemoState(msg.data as Record<string, unknown>)
            break
          case 'c2_beacon':
          case 'integrity_alert':
          case 'connected':
          case 'subscribed':
          case 'pong':
            break
          default:
            break
        }
      } catch {
        /* ignore malformed */
      }
    }

    socket.onerror = () => {
      set({ state: 'error', lastError: 'WebSocket error' })
    }

    socket.onclose = () => {
      set({ state: 'disconnected' })
      socket = null
      if (!intentionalClose) {
        scheduleReconnect(() => get().connect())
      }
    }
  },

  disconnect: () => {
    intentionalClose = true
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    socket?.close()
    socket = null
    set({ state: 'disconnected' })
  },

  send: (msg) => {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(msg))
    }
  },
}))
