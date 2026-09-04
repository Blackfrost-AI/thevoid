import { useEffect, useMemo, useRef, useState } from 'react'
import { NAV_ITEMS, useUiStore, type ViewId } from '../../store/ui'

interface CommandItem {
  id: string
  label: string
  group: string
  action: () => void
}

export function CommandPalette() {
  const open = useUiStore((s) => s.commandPaletteOpen)
  const setOpen = useUiStore((s) => s.setCommandPalette)
  const setView = useUiStore((s) => s.setView)
  const [q, setQ] = useState('')
  const [idx, setIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const items: CommandItem[] = useMemo(() => {
    const nav: CommandItem[] = NAV_ITEMS.map((n) => ({
      id: `nav-${n.id}`,
      label: `Go to ${n.label}`,
      group: 'Navigation',
      action: () => {
        setView(n.id as ViewId)
        setOpen(false)
      },
    }))
    const actions: CommandItem[] = [
      {
        id: 'act-refresh',
        label: 'Refresh engagement status',
        group: 'Actions',
        action: () => {
          window.dispatchEvent(new CustomEvent('void:refresh'))
          setOpen(false)
        },
      },
      {
        id: 'act-export-warlog',
        label: 'Export WarLog',
        group: 'Actions',
        action: () => {
          setView('warlog')
          setOpen(false)
          window.dispatchEvent(new CustomEvent('void:export-warlog'))
        },
      },
      {
        id: 'act-report',
        label: 'Generate report',
        group: 'Actions',
        action: () => {
          setView('reports')
          setOpen(false)
        },
      },
    ]
    return [...nav, ...actions]
  }, [setOpen, setView])

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase()
    if (!qq) return items
    return items.filter(
      (i) => i.label.toLowerCase().includes(qq) || i.group.toLowerCase().includes(qq),
    )
  }, [items, q])

  useEffect(() => {
    if (open) {
      setQ('')
      setIdx(0)
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  useEffect(() => {
    setIdx(0)
  }, [q])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen(!useUiStore.getState().commandPaletteOpen)
      }
      if (e.key === 'Escape' && useUiStore.getState().commandPaletteOpen) {
        setOpen(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [setOpen])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      style={{ background: 'rgba(0,0,0,0.55)' }}
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-lg rounded-md border border-void-line bg-void-elevated shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <input
          ref={inputRef}
          className="void-input w-full border-0 border-b border-void-line rounded-none px-4 py-3 text-[14px] bg-transparent"
          placeholder="Jump to view, run action…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              setIdx((i) => Math.min(i + 1, filtered.length - 1))
            } else if (e.key === 'ArrowUp') {
              e.preventDefault()
              setIdx((i) => Math.max(i - 1, 0))
            } else if (e.key === 'Enter' && filtered[idx]) {
              filtered[idx].action()
            }
          }}
        />
        <ul className="max-h-72 overflow-auto py-1">
          {filtered.length === 0 ? (
            <li className="px-4 py-3 text-void-text-mute text-[12px]">No matches</li>
          ) : (
            filtered.map((item, i) => (
              <li key={item.id}>
                <button
                  type="button"
                  className={`w-full text-left px-4 py-2 text-[12px] flex justify-between ${
                    i === idx ? 'bg-void-panel text-void-text' : 'text-void-text-dim hover:bg-void-panel'
                  }`}
                  onMouseEnter={() => setIdx(i)}
                  onClick={() => item.action()}
                >
                  <span>{item.label}</span>
                  <span className="text-void-text-mute text-[10px]">{item.group}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  )
}
