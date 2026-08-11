export type NormalizedStatus='HEALTHY'|'INFORMATIONAL'|'ATTENTION'|'WARNING'|'CRITICAL'|'INCONCLUSIVE'
export type Confidence='HIGH'|'MEDIUM'|'LOW'
export interface NavigationItem { label:string; href:string; icon:string }
export interface SummaryMetric { label:string; value:number; detail:string; status:NormalizedStatus }
export interface AssetSummary { id:string; name:string; type:string; environment:'INTERNAL'|'PUBLIC'; criticality:'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'; status:NormalizedStatus; lastSeenAt:string|null }
export interface FindingSummary { id:string; title:string; status:string; priority:string; severity:string; confidence:Confidence; assetName:string; lastSeenAt:string|null }
export type JsonValue=string|number|boolean|null|JsonValue[]|{[key:string]:JsonValue}
export interface VantagePoint {id:string;name:string;agent_id:string|null;site:string|null;network_zone:string|null;environment:'INTERNAL'|'PUBLIC';active:boolean}
export interface NetworkService {id:string;asset_id:string;protocol:string;port:number;name:string;product:string|null;version:string|null;public_exposure:boolean;first_seen_at:string;last_seen_at:string;status:NormalizedStatus}
export interface Incident {id:string;title:string;description:string;status:'OPEN'|'INVESTIGATING'|'MONITORING'|'RESOLVED'|'CLOSED';severity:string|null;detected_at:string;resolved_at:string|null;primary_asset_id:string|null;root_cause_status:'UNKNOWN'|'SUSPECTED'|'IDENTIFIED'|'INCONCLUSIVE'}
export interface IncidentEvent {id:string;incident_id:string;event_type:string;title:string;description:string;status:NormalizedStatus;confidence:Confidence;source_type:string;source_id:string|null;occurred_at:string}
export interface AgentDetail {id:string;name:string;hostname:string;os:string;arch:string;version:string;protocol_version:string;compatibility_status:'COMPATIBLE'|'UPGRADE_RECOMMENDED'|'INCOMPATIBLE'|'UNKNOWN';status:string;last_seen_at:string|null;registered_at:string;capabilities:JsonValue;capabilities_manifest:JsonValue;network_zone:string|null;identity_fingerprint:string;available_slots:number;running_jobs:number}
