package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
)

type resourceQuery struct {
	from         string
	columns      string
	organization string
	order        string
}

var resourceQueries = map[string]resourceQuery{
	"users":             {"users", "id,organization_id,name,email,active,last_login_at,created_at,updated_at,disabled_at", "organization_id=$1", "created_at DESC"},
	"roles":             {"roles", "id,organization_id,name,system", "(organization_id=$1 OR organization_id IS NULL)", "name"},
	"permissions":       {"permissions", "id,name,description", "($1::text IS NOT NULL AND $2::text IS NOT NULL)", "name"},
	"assets":            {"assets", "id,organization_id,name,type,hostname,host(ip_address) AS ip_address,environment,criticality,owner,description,first_seen_at,last_seen_at,status,created_at,updated_at", "organization_id=$1", "updated_at DESC"},
	"scopes":            {"authorized_scopes", "id,organization_id,type,value,environment,status,verification_type,verified_at,verified_by,valid_from,valid_until,notes,created_at", "organization_id=$1", "created_at DESC"},
	"agents":            {"agents", "id,organization_id,name,hostname,os,arch,version,protocol_version,compatibility_status,status,last_seen_at,registered_at,capabilities,capabilities_manifest,capabilities_hash,available_slots,running_jobs,health_summary,labels,network_zone,identity_fingerprint,identity_rotated_at,certificate_expires_at", "organization_id=$1", "registered_at DESC"},
	"vantage-points":    {"vantage_points", "id,organization_id,name,agent_id,site,network_zone,environment,labels,active,created_at,updated_at", "organization_id=$1", "name"},
	"services":          {"network_services", "id,organization_id,asset_id,protocol,port,name,product,version,public_exposure,first_seen_at,last_seen_at,status,created_at,updated_at", "organization_id=$1", "last_seen_at DESC"},
	"public-exposure":   {"network_services", "id,organization_id,asset_id,protocol,port,name,product,version,public_exposure,first_seen_at,last_seen_at,status,created_at,updated_at", "organization_id=$1 AND public_exposure", "last_seen_at DESC"},
	"diagnostic-runs":   {"diagnostic_runs", "id,organization_id,asset_id,service_id,requested_by,profile_id,status,started_at,completed_at,summary,confidence,created_at", "organization_id=$1", "created_at DESC"},
	"jobs":              {"analysis_jobs", "id,organization_id,module_id,asset_id,service_id,diagnostic_run_id,vantage_point_id,scope_id,agent_id,requested_by,parameters,risk_class,protocol_version,authorization_reference,status,created_at,queued_at,started_at,completed_at,timeout_at,rejection_code,result_identity,result_version", "organization_id=$1", "created_at DESC"},
	"schedules":         {"schedules", "id,organization_id,module_id,scope_id,agent_id,asset_id,service_id,vantage_point_id,parameters,frequency_seconds,enabled,next_run_at,created_by,created_at", "organization_id=$1", "created_at DESC"},
	"observations":      {"observations", "id,organization_id,asset_id,module_id,job_id,category,status,severity,confidence,title,summary,meaning,impact,suggested_action,observed_at,evidence_count", "organization_id=$1", "observed_at DESC"},
	"findings":          {"findings", "id,organization_id,asset_id,source_observation_id,category,severity,priority,confidence,title,description,remediation,status,first_seen_at,last_seen_at,resolved_at,resolved_by,risk_factors", "organization_id=$1", "last_seen_at DESC"},
	"evidence":          {"evidence", "id,organization_id,job_id,observation_id,finding_id,module_id,agent_id,vantage_point_id,source,artifact_kind,content_type,summary,structured_data,checksum,size_bytes,observed_at,raw_access_required,created_at,(storage_key IS NOT NULL) AS has_raw_artifact", "organization_id=$1", "created_at DESC"},
	"incidents":         {"incidents", "id,organization_id,title,description,status,severity,started_at,detected_at,resolved_at,created_by,assigned_to,primary_asset_id,root_cause_status,created_at,updated_at", "organization_id=$1", "detected_at DESC"},
	"incident-events":   {"incident_events", "id,organization_id,incident_id,event_type,title,description,status,confidence,source_type,source_id,occurred_at,created_by,created_at", "organization_id=$1", "occurred_at DESC"},
	"incident-reports":  {"incident_evidence_reports", "id,organization_id,incident_id,status,confidence,summary,known_limitations,suggested_actions,(storage_key IS NOT NULL) AS downloadable,created_by,created_at,completed_at", "organization_id=$1", "created_at DESC"},
	"route-snapshots":   {"route_snapshots", "id,organization_id,asset_id,service_id,job_id,vantage_point_id,destination,status,captured_at,created_at", "organization_id=$1", "captured_at DESC"},
	"route-comparisons": {"route_comparisons", "id,organization_id,asset_id,previous_snapshot_id,current_snapshot_id,status,first_divergence_hop,summary,confidence,compared_at", "organization_id=$1", "compared_at DESC"},
	"monitor-history":   {"monitor_samples", "id,organization_id,asset_id,service_id,vantage_point_id,job_id,metric,numeric_value,text_value,status,observed_at", "organization_id=$1", "observed_at DESC"},
	"baselines":         {"operational_baselines", "id,organization_id,asset_id,service_id,vantage_point_id,metric,sample_count,minimum_value,maximum_value,typical_low,typical_high,window_start,window_end,calculated_at", "organization_id=$1", "calculated_at DESC"},
	"changes":           {"change_observations", "id,organization_id,asset_id,service_id,vantage_point_id,observation_id,change_type,status,confidence,previous_value,current_value,explanation,observed_at", "organization_id=$1", "observed_at DESC"},
	"vulnerabilities":   {"vulnerabilities", "id,organization_id,asset_id,cve,name,description,cvss_score,cvss_version,scanner_severity,affected_service,evidence_id,remediation,first_seen_at,last_seen_at", "organization_id=$1", "last_seen_at DESC"},
	"traffic":           {"traffic_observations", "id,organization_id,asset_id,job_id,source,observation_type,occurred_at,summary,(metadata_storage_key IS NOT NULL) AS has_raw_metadata", "organization_id=$1", "occurred_at DESC"},
	"pcap":              {"pcap_artifacts", "id,organization_id,uploaded_by,original_filename,content_length,checksum,captured_at,uploaded_at,expires_at,deleted_at,classification", "organization_id=$1", "uploaded_at DESC"},
	"reports":           {"reports", "id,organization_id,type,title,status,parameters,(storage_key IS NOT NULL) AS downloadable,created_by,created_at,completed_at", "organization_id=$1", "created_at DESC"},
	"notifications":     {"notifications", "id,organization_id,user_id,type,title,body,read_at,created_at", "organization_id=$1 AND (user_id IS NULL OR user_id=$2)", "created_at DESC"},
	"audit":             {"audit_events", "id,organization_id,actor_user_id,actor_agent_id,event_type,resource_type,resource_id,request_id,outcome,metadata,previous_hash,event_hash,created_at", "organization_id=$1", "created_at DESC"},
}

type Resources struct{ Pool *pgxpool.Pool }

func (r Resources) List(ctx context.Context, organizationID, userID domain.ID, resource string, limit, offset int) (json.RawMessage, error) {
	query, ok := resourceQueries[resource]
	if !ok {
		return nil, errors.New("resource is not registered")
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	sql := fmt.Sprintf(`SELECT coalesce(jsonb_agg(to_jsonb(item)),'[]'::jsonb) FROM (SELECT %s FROM %s WHERE %s ORDER BY %s LIMIT $3 OFFSET $4) item`, query.columns, query.from, query.organization, query.order)
	var data []byte
	if err := r.Pool.QueryRow(ctx, sql, organizationID, userID, limit, offset).Scan(&data); err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

func (r Resources) Get(ctx context.Context, organizationID, userID domain.ID, resource string, id domain.ID) (json.RawMessage, error) {
	query, ok := resourceQueries[resource]
	if !ok {
		return nil, errors.New("resource is not registered")
	}
	sql := fmt.Sprintf(`SELECT to_jsonb(item) FROM (SELECT %s FROM %s WHERE %s AND id=$3) item`, query.columns, query.from, query.organization)
	var data []byte
	if err := r.Pool.QueryRow(ctx, sql, organizationID, userID, id).Scan(&data); err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}
