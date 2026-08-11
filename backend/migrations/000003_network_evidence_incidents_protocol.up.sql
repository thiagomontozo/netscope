CREATE TYPE agent_compatibility_status AS ENUM ('COMPATIBLE','UPGRADE_RECOMMENDED','INCOMPATIBLE','UNKNOWN');
CREATE TYPE incident_status AS ENUM ('OPEN','INVESTIGATING','MONITORING','RESOLVED','CLOSED');
CREATE TYPE root_cause_status AS ENUM ('UNKNOWN','SUSPECTED','IDENTIFIED','INCONCLUSIVE');
CREATE TYPE incident_evidence_role AS ENUM ('KEY_EVIDENCE','SUPPORTING_EVIDENCE','CONTEXT');
CREATE TYPE route_comparison_status AS ENUM ('UNCHANGED','CHANGED','PARTIALLY_CHANGED','INCONCLUSIVE');

ALTER TABLE module_definitions
  ADD COLUMN protocol_version text NOT NULL DEFAULT '1.0',
  ADD COLUMN supported_platforms text[] NOT NULL DEFAULT '{linux,windows,darwin}',
  ADD COLUMN parameter_schema_version text NOT NULL DEFAULT '1.0',
  ADD COLUMN result_schema_version text NOT NULL DEFAULT '1.0';

ALTER TABLE agents
  ADD COLUMN protocol_version text NOT NULL DEFAULT '0.0',
  ADD COLUMN compatibility_status agent_compatibility_status NOT NULL DEFAULT 'UNKNOWN',
  ADD COLUMN capabilities_manifest jsonb NOT NULL DEFAULT '{"modules":[],"externalTools":[],"networkCapabilities":[],"artifactCapabilities":[]}',
  ADD COLUMN capabilities_hash text,
  ADD COLUMN heartbeat_interval_seconds integer NOT NULL DEFAULT 30 CHECK(heartbeat_interval_seconds BETWEEN 10 AND 3600),
  ADD COLUMN available_slots integer NOT NULL DEFAULT 0 CHECK(available_slots >= 0),
  ADD COLUMN running_jobs integer NOT NULL DEFAULT 0 CHECK(running_jobs >= 0),
  ADD COLUMN health_summary jsonb NOT NULL DEFAULT '{}';

CREATE TABLE vantage_points (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  agent_id uuid REFERENCES agents(id) ON DELETE SET NULL,
  site text,
  network_zone text,
  environment scope_environment NOT NULL,
  labels jsonb NOT NULL DEFAULT '{}',
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,name)
);
CREATE UNIQUE INDEX vantage_points_agent_idx ON vantage_points(organization_id,agent_id) WHERE agent_id IS NOT NULL;

CREATE TABLE network_services (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  protocol text NOT NULL,
  port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
  name text NOT NULL,
  product text,
  version text,
  public_exposure boolean NOT NULL DEFAULT false,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  status normalized_status NOT NULL DEFAULT 'INFORMATIONAL',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,asset_id,protocol,port)
);
CREATE INDEX network_services_asset_idx ON network_services(organization_id,asset_id,last_seen_at DESC);
CREATE INDEX network_services_public_idx ON network_services(organization_id,last_seen_at DESC) WHERE public_exposure;

CREATE TABLE diagnostic_profiles (
  id text PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL,
  module_ids text[] NOT NULL,
  public_allowed boolean NOT NULL DEFAULT false,
  enabled boolean NOT NULL DEFAULT true
);
INSERT INTO diagnostic_profiles(id,name,description,module_ids,public_allowed) VALUES
('CONNECTIVITY','Connectivity','Bounded reachability and transport checks.','{network.ping,network.tcp}',false),
('WEB_SERVICE','Web service','DNS, TCP, TLS and bounded HTTP checks.','{network.dns,network.tcp,network.tls,network.http}',false),
('DNS','DNS','Approved DNS record resolution.','{network.dns}',true),
('TLS','TLS','TLS handshake and certificate metadata.','{network.tls}',true),
('NETWORK_PATH','Network path','Reachability and normalized route path.','{network.ping,network.route}',false),
('PUBLIC_SERVICE_HEALTH','Public service health','Safe DNS, TCP, TLS and HTTP checks from approved public vantage points.','{network.dns,network.tcp,network.tls,network.http}',true),
('FULL_SAFE_DIAGNOSTIC','Full safe diagnostic','All safe active diagnostic modules.','{network.ping,network.route,network.dns,network.tcp,network.tls,network.http}',false);

CREATE TABLE diagnostic_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  service_id uuid REFERENCES network_services(id),
  requested_by uuid NOT NULL REFERENCES users(id),
  profile_id text NOT NULL REFERENCES diagnostic_profiles(id),
  status text NOT NULL CHECK(status IN ('PENDING','RUNNING','COMPLETED','FAILED','CANCELLED','INCONCLUSIVE')),
  started_at timestamptz,
  completed_at timestamptz,
  summary text NOT NULL DEFAULT '',
  confidence confidence_level NOT NULL DEFAULT 'LOW',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX diagnostic_runs_asset_idx ON diagnostic_runs(organization_id,asset_id,created_at DESC);

ALTER TABLE schedules
  ADD COLUMN asset_id uuid REFERENCES assets(id),
  ADD COLUMN service_id uuid REFERENCES network_services(id),
  ADD COLUMN vantage_point_id uuid REFERENCES vantage_points(id),
  ADD COLUMN parameters jsonb NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(parameters)='object');

ALTER TABLE analysis_jobs
  ADD COLUMN service_id uuid REFERENCES network_services(id),
  ADD COLUMN diagnostic_run_id uuid REFERENCES diagnostic_runs(id),
  ADD COLUMN vantage_point_id uuid REFERENCES vantage_points(id),
  ADD COLUMN protocol_version text NOT NULL DEFAULT '1.0',
  ADD COLUMN authorization_reference text,
  ADD COLUMN result_identity text,
  ADD COLUMN result_version integer;
CREATE INDEX jobs_diagnostic_run_idx ON analysis_jobs(organization_id,diagnostic_run_id) WHERE diagnostic_run_id IS NOT NULL;

CREATE TABLE agent_result_receipts (
  job_id uuid PRIMARY KEY REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  agent_id uuid NOT NULL REFERENCES agents(id),
  result_identity text NOT NULL,
  result_version integer NOT NULL CHECK(result_version > 0),
  payload_checksum text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,agent_id,result_identity,result_version)
);

CREATE TABLE job_cancellation_requests (
  job_id uuid PRIMARY KEY REFERENCES analysis_jobs(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  requested_by uuid REFERENCES users(id),
  reason text NOT NULL DEFAULT '',
  requested_at timestamptz NOT NULL DEFAULT now(),
  acknowledged_at timestamptz
);

ALTER TABLE evidence
  ADD COLUMN module_id text REFERENCES module_definitions(id),
  ADD COLUMN agent_id uuid REFERENCES agents(id),
  ADD COLUMN vantage_point_id uuid REFERENCES vantage_points(id),
  ADD COLUMN artifact_kind text,
  ADD COLUMN size_bytes bigint CHECK(size_bytes IS NULL OR size_bytes >= 0),
  ADD COLUMN observed_at timestamptz;
UPDATE evidence e SET module_id=j.module_id,agent_id=j.agent_id,observed_at=e.created_at
FROM analysis_jobs j WHERE j.id=e.job_id;
CREATE INDEX evidence_provenance_idx ON evidence(organization_id,agent_id,module_id,created_at DESC);

CREATE TABLE evidence_references (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  evidence_id uuid NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  reference_type text NOT NULL CHECK(reference_type IN ('STRUCTURED_RESULT','RAW_OUTPUT','PCAP_ARTIFACT','TLS_METADATA','DNS_RESPONSE','ROUTE_HOPS','HTTP_TRANSACTION','NMAP_RESULT','ZEEK_EVENT','SURICATA_EVENT','VULNERABILITY_EVIDENCE')),
  reference_id text NOT NULL,
  relationship text NOT NULL DEFAULT 'PRODUCED_BY',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,evidence_id,reference_type,reference_id)
);

CREATE TABLE evidence_artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  evidence_id uuid NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  storage_key text NOT NULL UNIQUE,
  content_type text NOT NULL,
  size_bytes bigint NOT NULL CHECK(size_bytes >= 0),
  sha256 text NOT NULL CHECK(length(sha256)=64),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  classification text NOT NULL DEFAULT 'SENSITIVE'
);

CREATE TABLE incidents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  status incident_status NOT NULL DEFAULT 'OPEN',
  severity text,
  started_at timestamptz,
  detected_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  created_by uuid NOT NULL REFERENCES users(id),
  assigned_to uuid REFERENCES users(id),
  primary_asset_id uuid REFERENCES assets(id),
  root_cause_status root_cause_status NOT NULL DEFAULT 'UNKNOWN',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incidents_org_status_idx ON incidents(organization_id,status,detected_at DESC);

CREATE TABLE incident_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  status normalized_status NOT NULL DEFAULT 'INFORMATIONAL',
  confidence confidence_level NOT NULL DEFAULT 'LOW',
  source_type text NOT NULL,
  source_id text,
  occurred_at timestamptz NOT NULL,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX incident_events_timeline_idx ON incident_events(organization_id,incident_id,occurred_at,id);

CREATE TABLE incident_links (
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  link_type text NOT NULL CHECK(link_type IN ('OBSERVATION','FINDING','DIAGNOSTIC_RUN','JOB','AGENT','ASSET','SERVICE')),
  linked_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(incident_id,link_type,linked_id)
);

CREATE TABLE incident_evidence (
  incident_id uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  evidence_id uuid NOT NULL REFERENCES evidence(id),
  role incident_evidence_role NOT NULL,
  rationale text NOT NULL DEFAULT '',
  added_by uuid NOT NULL REFERENCES users(id),
  added_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(incident_id,evidence_id)
);

CREATE TABLE incident_evidence_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  incident_id uuid NOT NULL REFERENCES incidents(id),
  status text NOT NULL CHECK(status IN ('PENDING','COMPLETED','FAILED')),
  confidence confidence_level NOT NULL,
  summary text NOT NULL,
  known_limitations text NOT NULL,
  suggested_actions text NOT NULL,
  storage_key text,
  created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);

CREATE TABLE route_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  service_id uuid REFERENCES network_services(id),
  job_id uuid NOT NULL REFERENCES analysis_jobs(id),
  vantage_point_id uuid REFERENCES vantage_points(id),
  destination text NOT NULL,
  status normalized_status NOT NULL,
  captured_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(organization_id,job_id)
);
CREATE INDEX route_snapshots_history_idx ON route_snapshots(organization_id,asset_id,vantage_point_id,captured_at DESC);

CREATE TABLE route_hops (
  route_snapshot_id uuid NOT NULL REFERENCES route_snapshots(id) ON DELETE CASCADE,
  sequence integer NOT NULL CHECK(sequence > 0),
  address text,
  hostname text,
  latency_samples_ms jsonb NOT NULL DEFAULT '[]',
  timed_out boolean NOT NULL DEFAULT false,
  PRIMARY KEY(route_snapshot_id,sequence)
);

CREATE TABLE route_comparisons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  previous_snapshot_id uuid NOT NULL REFERENCES route_snapshots(id),
  current_snapshot_id uuid NOT NULL REFERENCES route_snapshots(id),
  status route_comparison_status NOT NULL,
  first_divergence_hop integer,
  summary text NOT NULL,
  confidence confidence_level NOT NULL,
  compared_at timestamptz NOT NULL DEFAULT now(),
  CHECK(previous_snapshot_id <> current_snapshot_id),
  UNIQUE(organization_id,previous_snapshot_id,current_snapshot_id)
);

CREATE TABLE monitor_samples (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  service_id uuid REFERENCES network_services(id),
  vantage_point_id uuid REFERENCES vantage_points(id),
  job_id uuid NOT NULL REFERENCES analysis_jobs(id),
  metric text NOT NULL CHECK(metric IN ('AVAILABILITY','LATENCY_MS','PACKET_LOSS_PERCENT','DNS_DURATION_MS','TCP_CONNECT_DURATION_MS','TLS_DAYS_UNTIL_EXPIRATION','HTTP_DURATION_MS','HTTP_STATUS')),
  numeric_value double precision,
  text_value text,
  status normalized_status NOT NULL,
  observed_at timestamptz NOT NULL
);
CREATE INDEX monitor_samples_history_idx ON monitor_samples(organization_id,asset_id,service_id,vantage_point_id,metric,observed_at DESC);

CREATE TABLE operational_baselines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid NOT NULL REFERENCES assets(id),
  service_id uuid REFERENCES network_services(id),
  vantage_point_id uuid REFERENCES vantage_points(id),
  metric text NOT NULL,
  sample_count integer NOT NULL CHECK(sample_count > 0),
  minimum_value double precision,
  maximum_value double precision,
  typical_low double precision,
  typical_high double precision,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  calculated_at timestamptz NOT NULL DEFAULT now(),
  CHECK(window_end > window_start)
);

CREATE TABLE change_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  asset_id uuid REFERENCES assets(id),
  service_id uuid REFERENCES network_services(id),
  vantage_point_id uuid REFERENCES vantage_points(id),
  observation_id uuid REFERENCES observations(id),
  change_type text NOT NULL CHECK(change_type IN ('SERVICE_DISCOVERED','SERVICE_DISAPPEARED','TLS_CERTIFICATE_CHANGED','DNS_ADDRESS_CHANGED','ROUTE_CHANGED','HTTP_STATUS_PATTERN_CHANGED','AGENT_CAPABILITY_CHANGED')),
  status normalized_status NOT NULL DEFAULT 'INFORMATIONAL',
  confidence confidence_level NOT NULL,
  previous_value jsonb,
  current_value jsonb,
  explanation text NOT NULL,
  observed_at timestamptz NOT NULL
);
CREATE INDEX change_observations_timeline_idx ON change_observations(organization_id,asset_id,observed_at DESC);

INSERT INTO permissions(name,description) VALUES
('services.read','Read network services'),
('services.manage','Manage network services'),
('incidents.read','Read incidents and timelines'),
('incidents.manage','Manage incidents and incident evidence')
ON CONFLICT(name) DO NOTHING;

INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.system AND p.name IN ('services.read','incidents.read')
  AND r.name IN ('Owner','Administrator','Security Administrator','Security Analyst','Network Analyst','Operator','Viewer')
ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p
WHERE r.system AND p.name IN ('services.manage','incidents.manage')
  AND r.name IN ('Owner','Administrator','Security Administrator','Security Analyst','Network Analyst','Operator')
ON CONFLICT DO NOTHING;
