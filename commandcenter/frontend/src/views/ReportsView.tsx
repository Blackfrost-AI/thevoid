import { useState } from 'react'
import { api } from '../api/client'
import { Panel, EmptyState } from '../components/common/Panel'

export function ReportsView() {
  const [format, setFormat] = useState('markdown')
  const [operator, setOperator] = useState('THE VOID')
  const [name, setName] = useState('Authorized Security Assessment')
  const [content, setContent] = useState<string | null>(null)
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
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }

  const integrity = preview?.integrity as Record<string, unknown> | undefined

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
        ) : format === 'html' && content.trim().startsWith('<') ? (
          <iframe
            title="report"
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
