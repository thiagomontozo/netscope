import { AlertCircle, AlertTriangle, CheckCircle2, CircleEllipsis, Info, Siren } from 'lucide-react'
import type { NormalizedStatus } from '../types'
const styles:Record<NormalizedStatus,string>={HEALTHY:'bg-emerald-50 text-emerald-800 border-emerald-200',INFORMATIONAL:'bg-blue-50 text-blue-800 border-blue-200',ATTENTION:'bg-amber-50 text-amber-800 border-amber-200',WARNING:'bg-orange-50 text-orange-800 border-orange-200',CRITICAL:'bg-rose-50 text-rose-800 border-rose-200',INCONCLUSIVE:'bg-slate-100 text-slate-700 border-slate-300'}
const labels:Record<NormalizedStatus,string>={HEALTHY:'Healthy',INFORMATIONAL:'Informational',ATTENTION:'Attention',WARNING:'Warning',CRITICAL:'Critical',INCONCLUSIVE:'Inconclusive'}
const icons={HEALTHY:CheckCircle2,INFORMATIONAL:Info,ATTENTION:AlertCircle,WARNING:AlertTriangle,CRITICAL:Siren,INCONCLUSIVE:CircleEllipsis}
export function StatusBadge({status}:{status:NormalizedStatus}){const Icon=icons[status];return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${styles[status]}`}><Icon size={14} aria-hidden="true"/>{labels[status]}</span>}
