import { useEffect, useState } from 'react'
import { EmptyState } from '../components/EmptyState'
import { WorkflowPanel } from '../components/WorkflowPanel'
import { apiGet, ApiError } from '../services/api'

type RecordValue = string | number | boolean | null | Record<string, unknown> | unknown[]
interface ListResponse { data: Array<Record<string, RecordValue>> }

const preferredColumns: Record<string, string[]> = {
  artifacts: ['type', 'direction', 'content_type', 'size_bytes', 'sha256', 'status', 'verified_at'],
  evidence: ['source', 'artifact_kind', 'artifact_id', 'job_id', 'agent_id', 'checksum', 'created_at'],
  jobs: ['module_id', 'agent_id', 'risk_class', 'signed', 'signing_key_id', 'signature_algorithm', 'signature_validation_status'],
}

function display(value: RecordValue): string {
  if (value === null) return '-'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export function ResourcePage({ title, description, resource }: { title: string; description: string; resource?: string }) {
  const [rows, setRows] = useState<Array<Record<string, RecordValue>>>([])
  const [message, setMessage] = useState('Loading...')
  useEffect(() => {
    if (!resource || resource === 'settings') {
      setMessage('Use the authorized workflow above.')
      return
    }
    const controller = new AbortController()
    apiGet<ListResponse>(`/${resource}`, controller.signal)
      .then((result) => {
        setRows(result.data)
        setMessage(result.data.length === 0 ? 'No organization-scoped records are available.' : '')
      })
      .catch((error) => setMessage(error instanceof ApiError ? `${error.message} (request ${error.requestId})` : 'The records could not be loaded.'))
    return () => controller.abort()
  }, [resource])

  const requested = resource ? preferredColumns[resource] : undefined
  const columns = rows.length > 0 ? (requested ?? Object.keys(rows[0]).slice(0, 7)).filter((column) => column in rows[0]) : []
  return <div className="space-y-6">
    <header><p className="eyebrow">NetScope workspace</p><h1 className="mt-1 text-3xl font-bold tracking-tight">{title}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slateblue">{description}</p></header>
    {resource && <WorkflowPanel resource={resource} />}
    <div className="card overflow-hidden">{rows.length === 0 ? <div className="p-5"><EmptyState title={message} detail="Missing data is shown as inconclusive, never as healthy." /></div> : <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-b border-line bg-panel"><tr>{columns.map((column) => <th className="px-4 py-3 font-semibold" key={column}>{column.replaceAll('_', ' ')}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr className="border-b border-line last:border-0" key={String(row.id ?? index)}>{columns.map((column) => <td className="max-w-xs truncate px-4 py-3 text-slateblue" key={column}>{display(row[column])}</td>)}</tr>)}</tbody></table></div>}</div>
  </div>
}
