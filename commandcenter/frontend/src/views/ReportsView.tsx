import { useState } from 'react'
import { api } from '../api/client'
import { Panel, EmptyState } from '../components/common/Panel'

export function ReportsView() {
  const [format, setFormat] = useState('markdown')
  const [operator, setOperator] = useState('THE VOID')
  const [name, setName] = useState('Authorized Security Assessment')
  const [content, setContent] = useState<string | null>(null)
  const [contentFormat, setContentFormat] = useState('json')
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadPreview = async () => {
    setBusy(true)
    setError(null)
    try {
      const data = await api.reportPreview(operator, name)
      setPreview(data)
      setContent(JSON.stringify(data, null, 2))
      setContentFormat('json')
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const generate = async () => {
    setBusy(true)
    setError(null)
    try {
      const r = await api.reportGenerate({
        format,
        operator,
        engagement_name: name,
      })
      setContent(r.content)
      setContentFormat(r.format)
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const integrity = preview?.integrity as Record<string, unknown> | undefined

  const downloadReport = () => {
    if (!content) return
    const normalized = contentFormat === 'md' ? 'markdown' : contentFormat
    const extension = normalized === 'markdown' ? 'md' : normalized
    const mime =
      normalized === 'html'
        ? 'text/html'
        : normalized === 'json'
          ? 'application/json'
          : 'text/markdown'
    const url = URL.createObjectURL(new Blob([content], { type: `${mime};charset=utf-8` }))
    const link = document.createElement('a')
    link.href = url
    link.download = `void-report.${extension}`
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  return (
    <div className="h-full flex flex-col gap-3">
      <Panel
        title="Report Generator"
        actions={
          <>
            <button type="button" className="void-btn" onClick={loadPreview} disabled={busy}>
              Preview data
            </button>
            <button type="button" className="void-btn primary" onClick={generate} disabled={busy}>
              Generate
            </button>
            {content ? (
              <button type="button" className="void-btn" onClick={downloadReport} disabled={busy}>
                Download
              </button>
            ) : null}
          </>
        }
      >
        <div className="flex flex-wrap gap-3 items-end">
          <label className="flex flex-col gap-1 text-[11px] text-void-text-mute">
            Format
            <select className="void-input" value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="json">JSON</option>
              <option value="markdown">Markdown</option>
              <option value="html">HTML</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-void-text-mute">
            Operator
            <input
              className="void-input w-40"
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-void-text-mute">
            Engagement name
            <input
              className="void-input w-64"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
        </div>
        {error ? <p className="mt-2 text-void-error text-[12px]">{error}</p> : null}
      </Panel>

      {integrity ? (
        <Panel title="Integrity Report">
          <pre className="text-[11px] mono text-void-text-dim overflow-auto max-h-40">
            {JSON.stringify(integrity, null, 2)}
          </pre>
        </Panel>
      ) : null}

      <Panel title="Preview" className="flex-1 min-h-0" bodyClassName="!p-0 overflow-auto">
        {!content ? (
          <div className="p-3">
            <EmptyState message="Generate or preview a report to view content." />
          </div>
        ) : contentFormat === 'html' && content.trim().startsWith('<') ? (
          <iframe
            title="report"
            sandbox=""
            referrerPolicy="no-referrer"
            className="w-full h-full min-h-[400px] bg-white"
            srcDoc={content}
          />
        ) : (
          <pre className="p-3 text-[11px] mono text-void-text-dim whitespace-pre-wrap">{content}</pre>
        )}
      </Panel>
    </div>
  )
}
