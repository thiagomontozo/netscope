export type NormalizedStatus='HEALTHY'|'INFORMATIONAL'|'ATTENTION'|'WARNING'|'CRITICAL'|'INCONCLUSIVE'
export type Confidence='HIGH'|'MEDIUM'|'LOW'
export interface NavigationItem { label:string; href:string; icon:string }
export interface SummaryMetric { label:string; value:number; detail:string; status:NormalizedStatus }
export interface AssetSummary { id:string; name:string; type:string; environment:'INTERNAL'|'PUBLIC'; criticality:'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'; status:NormalizedStatus; lastSeenAt:string|null }
export interface FindingSummary { id:string; title:string; status:string; priority:string; severity:string; confidence:Confidence; assetName:string; lastSeenAt:string|null }
