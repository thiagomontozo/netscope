import { useEffect, useState } from 'react'
import { MapPin, Network, Route, Timer } from 'lucide-react'
import { EmptyState } from '../components/EmptyState'
import { StatusBadge } from '../components/StatusBadge'
import { ApiError, apiGet } from '../services/api'
import type { VantagePoint } from '../types'

interface VantageResponse { data: VantagePoint[] }
export function MultiVantagePage() {
  const [points, setPoints] = useState<VantagePoint[]>([])
  const [message, setMessage] = useState('Loading vantage points...')
  useEffect(() => {
    const controller = new AbortController()
    apiGet<VantageResponse>('/vantage-points', controller.signal).then((result) => { setPoints(result.data); setMessage(result.data.length ? '' : 'No vantage points are configured.') }).catch((error) => setMessage(error instanceof ApiError ? `${error.message} (request ${error.requestId})` : 'Vantage points could not be loaded.'))
    return () => controller.abort()
  }, [])
  const concepts = [['Connectivity', 'Direct protocol response', Network], ['Network path', 'First observed divergence', Route], ['Performance', 'Recent baseline context', Timer]] as const
  return <div className="space-y-6">
    <header><p className="eyebrow">Multi-vantage diagnostics</p><h1 className="mt-1 text-3xl font-bold">Separate service state from location-specific failure.</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-slateblue">Compare DNS, reachability, latency, TLS, HTTP and routes from approved agents. Conflicting results remain visible and do not become a global outage automatically.</p></header>
    <section className="grid gap-3 md:grid-cols-3">{concepts.map(([label, detail, Icon]) => <article className="card p-5" key={label}><Icon className="text-brand" /><h2 className="mt-4 font-bold">{label}</h2><p className="mt-1 text-sm text-slateblue">{detail}</p></article>)}</section>
    <section className="card p-5"><div className="flex items-center gap-2"><MapPin size={19} className="text-brand" /><h2 className="font-bold">Available vantage points</h2></div>{points.length === 0 ? <div className="mt-5"><EmptyState title={message} detail="Associate an outbound agent with a site, branch, datacenter, DMZ or cloud location before comparing observations." /></div> : <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">{points.map((point) => <article key={point.id} className="rounded-lg border border-line p-4"><div className="flex items-center justify-between"><h3 className="font-semibold">{point.name}</h3><StatusBadge status={point.active ? 'INFORMATIONAL' : 'INCONCLUSIVE'} explanation={point.active ? 'Vantage point is available for authorized scheduling.' : 'Vantage point is inactive.'} /></div><p className="mt-2 text-sm text-slateblue">{point.site ?? 'Site not specified'} · {point.network_zone ?? 'zone not specified'} · {point.environment}</p></article>)}</div>}</section>
    <div className="rounded-xl border border-blue-200 bg-blue-50 p-4 text-sm leading-6 text-blue-900">Example interpretation: “Service is reachable from two vantage points but unreachable from one. The issue may be path- or location-specific.”</div>
  </div>
}
