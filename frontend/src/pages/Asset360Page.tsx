import { useEffect, useState } from 'react'
import { Activity, Clock3, Globe2, Network, Server, ShieldCheck, Signal, Waypoints } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { EmptyState } from '../components/EmptyState'
import { StatusBadge } from '../components/StatusBadge'
import { ApiError, apiGet } from '../services/api'
import type { Incident, NetworkService, NormalizedStatus } from '../types'

interface Asset {
  id: string
  name: string
  hostname: string | null
  ip_address: string | null
  environment: 'INTERNAL' | 'PUBLIC'
  criticality: string
  status: NormalizedStatus
  last_seen_at: string
}
interface AssetResponse { data: Asset }
interface ServiceList { data: NetworkService[] }
interface IncidentList { data: Incident[] }

const tabs = ['Overview', 'Connectivity', 'Services', 'Routes', 'Traffic', 'Security', 'Performance', 'Incidents', 'Timeline', 'Evidence']

export function Asset360Page() {
  const { id } = useParams()
  const [asset, setAsset] = useState<Asset | null>(null)
  const [services, setServices] = useState<NetworkService[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [message, setMessage] = useState('Loading Asset 360...')

  useEffect(() => {
    if (!id) return
    const controller = new AbortController()
    Promise.all([
      apiGet<AssetResponse>(`/assets/${id}`, controller.signal),
      apiGet<ServiceList>('/services?limit=200', controller.signal),
      apiGet<IncidentList>('/incidents?limit=200', controller.signal),
    ]).then(([assetResult, serviceResult, incidentResult]) => {
      setAsset(assetResult.data)
      setServices(serviceResult.data.filter((item) => item.asset_id === id))
      setIncidents(incidentResult.data.filter((item) => item.primary_asset_id === id && item.status !== 'CLOSED'))
      setMessage('')
    }).catch((error) => setMessage(error instanceof ApiError ? `${error.message} (request ${error.requestId})` : 'Asset context could not be loaded.'))
    return () => controller.abort()
  }, [id])

  if (!asset) return <EmptyState title={message} detail="Asset state remains inconclusive when organization-scoped evidence cannot be loaded." />

  const publicServices = services.filter((service) => service.public_exposure)
  const metrics = [
    ['Reachability', asset.status === 'HEALTHY' ? 'Observed healthy' : 'Review evidence', Signal],
    ['Vantage coverage', 'Awaiting comparison', Activity],
    ['Services', String(services.length), Network],
    ['Active incidents', String(incidents.length), ShieldCheck],
  ] as const

  return <div className="space-y-6">
    <section className="card overflow-hidden">
      <div className="bg-gradient-to-r from-navy to-[#1e3d68] p-6 text-white">
        <div className="flex flex-col justify-between gap-5 md:flex-row md:items-start">
          <div className="flex gap-4"><div className="grid h-12 w-12 place-items-center rounded-xl bg-white/10"><Server /></div><div><p className="text-xs font-semibold uppercase tracking-[.14em] text-blue-200">Asset 360</p><h1 className="mt-1 text-2xl font-bold">{asset.name}</h1><p className="mt-2 text-sm text-slate-300">{asset.hostname ?? asset.ip_address ?? 'Technical identity not observed'} · {asset.environment} · criticality {asset.criticality}</p></div></div>
          <StatusBadge status={asset.status} explanation="Asset status is the latest normalized conclusion and is not proof of security." />
        </div>
      </div>
      <nav className="flex overflow-x-auto border-b border-line px-4" aria-label="Asset views">{tabs.map((tab, index) => <button key={tab} className={`focus-ring shrink-0 border-b-2 px-4 py-4 text-sm font-semibold ${index === 0 ? 'border-brand text-brand' : 'border-transparent text-slateblue'}`}>{tab}</button>)}</nav>
    </section>
    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">{metrics.map(([label, value, Icon]) => <article className="card p-5" key={label}><Icon className="text-brand" size={20} /><p className="mt-5 text-xs font-semibold uppercase tracking-wide text-slateblue">{label}</p><p className="mt-1 text-lg font-bold">{value}</p></article>)}</section>
    <section className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
      <div className="card p-5">
        <div className="flex items-center justify-between"><div><p className="eyebrow">Operational answer</p><h2 className="mt-1 text-lg font-bold">What changed, and from where?</h2></div><Waypoints className="text-slateblue" /></div>
        <div className="mt-5 grid gap-3 md:grid-cols-2"><div className="rounded-lg border border-line p-4"><p className="text-xs font-bold uppercase text-slateblue">Public exposure</p><p className="mt-2 font-semibold">{publicServices.length ? `${publicServices.length} recorded service(s)` : 'Not observed'}</p><p className="mt-1 text-xs text-slateblue">Absence here is not proof that no exposure exists.</p></div><div className="rounded-lg border border-line p-4"><p className="text-xs font-bold uppercase text-slateblue">Last successful diagnostic</p><p className="mt-2 font-semibold">Not yet correlated</p><p className="mt-1 text-xs text-slateblue">Job and vantage histories remain independently reviewable.</p></div></div>
        {services.length === 0 ? <div className="mt-5"><EmptyState title="No services inventoried" detail="A service must be linked to this asset before TLS, HTTP, exposure and vulnerability context can converge." /></div> : <div className="mt-5 space-y-2">{services.slice(0, 5).map((service) => <Link key={service.id} to={`/app/services/${service.id}`} className="flex items-center justify-between rounded-lg border border-line p-3 hover:bg-panel"><span className="font-semibold">{service.name} · {service.protocol.toUpperCase()} {service.port}</span><StatusBadge status={service.status} /></Link>)}</div>}
      </div>
      <aside className="card p-5"><div className="flex items-center gap-2"><Clock3 size={18} className="text-brand" /><h2 className="font-bold">Recent timeline</h2></div>{incidents.length === 0 ? <p className="mt-4 text-sm text-slateblue">No active incident is linked as primary to this asset.</p> : <div className="mt-4 space-y-3">{incidents.map((incident) => <Link className="block border-l-2 border-brand pl-4" key={incident.id} to={`/app/incidents/${incident.id}`}><p className="font-semibold">{incident.title}</p><p className="mt-1 text-xs text-slateblue">{incident.status} · root cause {incident.root_cause_status}</p></Link>)}</div>}<div className="mt-5 flex items-center gap-3 rounded-xl border border-dashed border-line bg-panel p-4 text-sm text-slateblue"><Globe2 size={18} /><span>Route, certificate, DNS and service changes appear only when supported by observations.</span></div></aside>
    </section>
  </div>
}
