import { useEffect, useState } from 'react'
import { Cpu, Fingerprint, KeyRound, MapPin, RadioTower, ShieldCheck, Workflow } from 'lucide-react'
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

  const expiry = agent.certificate_expires_at ? new Date(agent.certificate_expires_at) : null
  const notBefore = agent.certificate_not_before ? new Date(agent.certificate_not_before) : null
  const daysRemaining = expiry ? Math.ceil((expiry.getTime() - Date.now()) / 86_400_000) : null
  const certificateStatus = agent.status === 'REVOKED' ? 'REVOKED' : daysRemaining !== null && daysRemaining <= 0 ? 'EXPIRED' : 'ACTIVE'
  const certificateWarning = certificateStatus === 'REVOKED' ? 'Agent certificate revoked.' : daysRemaining !== null && daysRemaining <= 14 ? `Certificate expires in ${Math.max(daysRemaining, 0)} days. Certificate rotation recommended.` : null
  const facts = [['Status', agent.status, RadioTower], ['Protocol', agent.protocol_version, Cpu], ['Vantage', agent.network_zone ?? 'Unassigned', MapPin], ['Running jobs', String(agent.running_jobs), Workflow], ['Identity', agent.identity_fingerprint?.slice(0, 16) ?? 'Not recorded', Fingerprint]] as const

  return <div className="space-y-6">
    <header className="card p-6"><p className="eyebrow">Distributed Agent</p><div className="mt-2 flex flex-col justify-between gap-4 md:flex-row"><div><h1 className="text-3xl font-bold">{agent.name}</h1><p className="mt-2 text-sm text-slateblue">{agent.hostname} · {agent.os}/{agent.arch} · agent {agent.version}</p></div><StatusBadge status={compatibilityStatus[agent.compatibility_status]} explanation={`Protocol ${agent.protocol_version}: ${agent.compatibility_status.replaceAll('_', ' ').toLowerCase()}.`} /></div></header>
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">{facts.map(([label, value, Icon]) => <article className="card p-4" key={label}><Icon size={18} className="text-brand" /><p className="mt-3 text-xs font-bold uppercase text-slateblue">{label}</p><p className="mt-1 break-all font-semibold">{value}</p></article>)}</section>
    {certificateWarning && <section className="rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900">{certificateWarning}</section>}
    <section className="grid gap-5 lg:grid-cols-2"><div className="card p-5"><h2 className="font-bold">Capability manifest</h2><p className="mt-1 text-xs text-slateblue">Schema {agent.capability_schema_version ?? '1.0'} · contract {agent.contract_version ?? '1.0'}</p><pre className="mt-4 max-h-80 overflow-auto rounded-lg bg-panel p-4 text-xs text-slateblue">{JSON.stringify(agent.capabilities_manifest, null, 2)}</pre></div><div className="card p-5"><h2 className="font-bold">Trust and heartbeat</h2><dl className="mt-4 space-y-3 text-sm"><div><dt className="text-slateblue">Last heartbeat</dt><dd className="font-semibold">{agent.last_seen_at ? new Date(agent.last_seen_at).toLocaleString() : 'Never'}</dd></div><div><dt className="text-slateblue">Enrollment</dt><dd className="font-semibold">{new Date(agent.registered_at).toLocaleString()}</dd></div><div><dt className="text-slateblue">Available slots</dt><dd className="font-semibold">{agent.available_slots}</dd></div></dl><p className="mt-5 text-sm leading-6 text-slateblue">Agents connect outbound using their own mTLS identity. The Control Plane does not open a shell or administrative connection.</p></div></section>
    <section className="grid gap-5 lg:grid-cols-2"><article className="card p-5"><div className="flex items-center gap-2"><ShieldCheck size={18} className="text-brand" /><h2 className="font-bold">mTLS certificate</h2></div><dl className="mt-4 space-y-3 text-sm"><div><dt className="text-slateblue">Status</dt><dd className="font-semibold">{certificateStatus}</dd></div><div><dt className="text-slateblue">Not before</dt><dd className="font-semibold">{notBefore ? notBefore.toLocaleString() : 'Not recorded'}</dd></div><div><dt className="text-slateblue">Expires</dt><dd className="font-semibold">{expiry ? expiry.toLocaleString() : 'Not recorded'}</dd></div><div><dt className="text-slateblue">Days remaining</dt><dd className="font-semibold">{daysRemaining ?? 'Unknown'}</dd></div><div><dt className="text-slateblue">Fingerprint</dt><dd className="break-all font-mono text-xs">{agent.identity_fingerprint}</dd></div><div><dt className="text-slateblue">Rotation</dt><dd className="font-semibold">{agent.certificate_rotation_status ?? 'IDLE'}</dd></div><div><dt className="text-slateblue">Previous certificate</dt><dd className="break-all font-mono text-xs">{agent.previous_certificate_fingerprint ?? 'None recorded'}</dd></div><div><dt className="text-slateblue">Last rotation</dt><dd className="font-semibold">{agent.last_certificate_rotation_at ? new Date(agent.last_certificate_rotation_at).toLocaleString() : 'Never'}</dd></div></dl></article><article className="card p-5"><div className="flex items-center gap-2"><KeyRound size={18} className="text-brand" /><h2 className="font-bold">Job signing trust</h2></div><dl className="mt-4 space-y-3 text-sm"><div><dt className="text-slateblue">Signed job readiness</dt><dd className="font-semibold">{agent.signing_key_id ? 'TRUSTED' : 'UPGRADE REQUIRED FOR SIGNED JOBS'}</dd></div><div><dt className="text-slateblue">Signing key ID</dt><dd className="font-mono text-xs">{agent.signing_key_id ?? 'Not reported'}</dd></div><div><dt className="text-slateblue">Protocol compatibility</dt><dd className="font-semibold">{agent.compatibility_status}</dd></div></dl><p className="mt-5 text-sm text-slateblue">Artifact transfers are job-scoped and integrity checked. Authorization never grants general object-storage access.</p></article></section>
  </div>
}
