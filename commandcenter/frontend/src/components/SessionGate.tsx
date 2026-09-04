import { useEffect, useState, type ReactNode } from 'react'
import { sessionHeaders, sessionToken } from '../api/session'

export function SessionGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<'checking' | 'ready' | 'locked'>('checking')
  useEffect(() => {
    const controller = new AbortController()
    if (!sessionToken()) {
      setState('locked')
      return () => controller.abort()
    }
    fetch('/api/session', { headers: sessionHeaders(), signal: controller.signal })
      .then((response) => setState(response.ok ? 'ready' : 'locked'))
      .catch(() => { if (!controller.signal.aborted) setState('locked') })
    return () => controller.abort()
  }, [])
  if (state === 'ready') return children
  return (
    <main className="min-h-screen flex items-center justify-center p-8">
      <section className="max-w-lg rounded border border-void-border bg-void-panel p-8" aria-live="polite">
        <h1 className="text-xl mb-4">THE VOID — Local operator access</h1>
        {state === 'checking' ? <p>Checking this browser session…</p> : <>
          <p>Open Command Center from its desktop launcher to authorize this browser tab.</p>
          <p className="mt-3">If it is already running, use <code>thevoid-command-center open</code>.</p>
          <p className="mt-3 text-sm">Your local evidence is locked. No account or internet login is required.</p>
          <button className="void-btn mt-5" onClick={() => window.location.reload()}>Retry connection</button>
        </>}
      </section>
    </main>
  )
}
