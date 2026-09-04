import type { ReactNode } from 'react'

export function Panel({
  title,
  actions,
  children,
  className = '',
  bodyClassName = '',
}: {
  title: string
  actions?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={`panel flex flex-col min-h-0 ${className}`}>
      <div className="panel-header">
        <span>{title}</span>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </div>
      <div className={`panel-body flex-1 min-h-0 ${bodyClassName}`}>{children}</div>
    </section>
  )
}

export function Stat({
  label,
  value,
  tone,
}: {
  label: string
  value: string | number
  tone?: 'success' | 'warning' | 'error' | 'info'
}) {
  const color =
    tone === 'success'
      ? 'text-void-success'
      : tone === 'warning'
        ? 'text-void-warning'
        : tone === 'error'
          ? 'text-void-error'
          : tone === 'info'
            ? 'text-void-info'
            : 'text-void-text'
  return (
    <div className="flex flex-col gap-0.5 min-w-[72px]">
      <span className="text-[10px] uppercase tracking-wider text-void-text-mute">{label}</span>
      <span className={`text-[18px] font-semibold mono ${color}`}>{value}</span>
    </div>
  )
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="text-void-text-mute text-[12px] py-6 text-center border border-dashed border-void-line rounded">
      {message}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return <div className="text-void-text-dim text-[12px] py-4">{label}</div>
}
