import { useEffect, useState } from 'react'
import { Cpu, Fingerprint, MapPin, RadioTower, Workflow } from 'lucide-react'
import { useParams } from 'react-router-dom'
import { EmptyState } from '../components/EmptyState'
import { StatusBadge } from '../components/StatusBadge'
import { ApiError, apiGet } from '../services/api'
import type { AgentDetail, NormalizedStatus } from '../types'

interface AgentResponse { data: AgentDetail }
const compatibilityStatus: Record<AgentDetail['compatibility_status'], NormalizedStatus> = { COMPATIBLE: 'HEALTHY', UPGRADE_RECOMMENDED: 'ATTENTION', INCOMPATIBLE: 'WARNING', UNKNOWN: 'INCONCLUSIVE' }

export function AgentDetailPage() {
  const { id } = useParams()
  const [agent, setAgent] = useState<AgentDetail | null>(null)
  const [message, setMessage] = useState('Loading agent identity...')
  useEffect(() => {
    if (!id) return
    const controller = new AbortController()
    apiGet<AgentResponse>(`/agents/${id}`, controller.signal).then((result) => { setAgent(result.data); setMessage('') }).catch((error) => setMessage(error instanceof ApiError ? `${error.message} (request ${error.requestId})` : 'Agent could not be loaded.'))
    return () => controller.abort()
  }, [id])
  if (!agent) return <EmptyState title={message} detail="Agent compatibility cannot be inferred without a stored protocol version." />

  const identity = agent.identity_fingerprint ? agent.identity_fingerprint.slice(0, 16) : 'Not recorded'
  const facts = [['Status', agent.status, RadioTower], ['Protocol', agent.protocol_version, Cpu], ['Vantage', agent.network_zone ?? 'Unassigned', MapPin], ['Running jobs', String(agent.running_jobs), Workflow], ['Identity', identity, Fingerprint]] as const
  return <div className="space-y-6">
    <header className="card p-6"><p className="eyebrow">Distributed Agent</p><div className="mt-2 flex flex-col justify-between gap-4 md:flex-row"><div><h1 className="text-3xl font-bold">{agent.name}</h1><p className="mt-2 text-sm text-slateblue">{agent.hostname} · {agent.os}/{agent.arch} · agent {agent.version}</p></div><StatusBadge status={compatibilityStatus[agent.compatibility_status]} explanation={`Protocol ${agent.protocol_version}: ${agent.compatibility_status.replaceAll('_', ' ').toLowerCase()}.`} /></div></header>
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">{facts.map(([label, value, Icon]) => <article className="card p-4" key={label}><Icon size={18} className="text-brand" /><p className="mt-3 text-xs font-bold uppercase text-slateblue">{label}</p><p className="mt-1 break-all font-semibold">{value}</p></article>)}</section>
    <section className="grid gap-5 lg:grid-cols-2"><div className="card p-5"><h2 className="font-bold">Capability manifest</h2><pre className="mt-4 max-h-80 overflow-auto rounded-lg bg-panel p-4 text-xs text-slateblue">{JSON.stringify(agent.capabilities_manifest, null, 2)}</pre></div><div className="card p-5"><h2 className="font-bold">Trust and heartbeat</h2><dl className="mt-4 space-y-3 text-sm"><div><dt className="text-slateblue">Last heartbeat</dt><dd className="font-semibold">{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}</dd></div><div><dt className="text-slateblue">Enrollment</dt><dd className="font-semibold">{new Date(agent.registered_at).toLocaleString()}</dd></div><div><dt className="text-slateblue">Available slots</dt><dd className="font-semibold">{agent.available_slots}</dd></div></dl><p className="mt-5 text-sm leading-6 text-slateblue">Agents connect outbound using their own mTLS identity. The Control Plane does not open a shell or administrative connection.</p></div></section>
  </div>
}
