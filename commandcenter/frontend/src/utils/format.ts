export function fmtEpoch(epoch?: number | null): string {
  if (epoch == null || Number.isNaN(Number(epoch))) return '—'
  try {
    return new Date(Number(epoch) * 1000).toISOString().replace('T', ' ').slice(0, 19)
  } catch {
    return '—'
  }
}

export function fmtTs(ts?: string | null): string {
  if (!ts) return '—'
  try {
    return new Date(ts).toISOString().replace('T', ' ').slice(0, 19)
  } catch {
    return ts
  }
}

export function trunc(s: unknown, n = 48): string {
  const str = s == null ? '' : String(s)
  return str.length > n ? str.slice(0, n - 1) + '…' : str
}

export function levelClass(level?: string): string {
  const l = (level || '').toLowerCase()
  if (['error', 'critical', 'exploit', 'exfil'].includes(l)) return 'error'
  if (['warning', 'stealth'].includes(l)) return 'warning'
  if (['c2', 'recon', 'info'].includes(l)) return 'info'
  if (['agent'].includes(l)) return 'success'
  return ''
}

export function statusClass(status?: string): string {
  const s = (status || '').toLowerCase()
  if (['active', 'ok', 'healthy', 'success', 'verified', 'live'].includes(s)) return 'success'
  if (['degraded', 'pending', 'warning'].includes(s)) return 'warning'
  if (['failed', 'error', 'closed', 'breached', 'tampered'].includes(s)) return 'error'
  if (['running', 'info'].includes(s)) return 'info'
  return ''
}
