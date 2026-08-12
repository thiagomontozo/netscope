CREATE TYPE agent_certificate_status AS ENUM ('ACTIVE','ROTATING','REVOKED','EXPIRED','SUPERSEDED');
CREATE TYPE artifact_direction AS ENUM ('CONTROL_PLANE_TO_AGENT','AGENT_TO_CONTROL_PLANE');
CREATE TYPE artifact_status AS ENUM ('PENDING','UPLOADING','AVAILABLE','FAILED','EXPIRED');

CREATE TABLE agent_certificates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  serial_number text NOT NULL,
  fingerprint text NOT NULL CHECK(fingerprint ~ '^[a-f0-9]{64}$'),
  not_before timestamptz NOT NULL,
  not_after timestamptz NOT NULL,
  status agent_certificate_status NOT NULL,
  issued_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  replaced_by uuid REFERENCES agent_certificates(id),
  CHECK(not_after > not_before),
  UNIQUE(organization_id,serial_number),
  UNIQUE(organization_id,fingerprint)
);
CREATE INDEX agent_certificates_agent_idx ON agent_certificates(organization_id,agent_id,status,not_after);

CREATE TABLE artifacts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  job_id uuid REFERENCES analysis_jobs(id) ON DELETE SET NULL,
  type text NOT NULL CHECK(type IN ('PCAP','RAW_EVIDENCE','JOB_INPUT','JOB_OUTPUT','REPORT')),
  direction artifact_direction NOT NULL,
  content_type text NOT NULL,
  original_name text,
  storage_key text NOT NULL UNIQUE,
  size_bytes bigint NOT NULL CHECK(size_bytes >= 0),
  sha256 text NOT NULL CHECK(sha256 ~ '^[a-f0-9]{64}$'),
  status artifact_status NOT NULL DEFAULT 'PENDING',
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  uploaded_by_agent_id uuid REFERENCES agents(id) ON DELETE SET NULL,
  verified_at timestamptz,
  CHECK(expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX artifacts_job_idx ON artifacts(organization_id,job_id,created_at DESC);
CREATE INDEX artifacts_retention_idx ON artifacts(organization_id,type,expires_at) WHERE status='AVAILABLE';

ALTER TABLE analysis_jobs
  ADD COLUMN signing_key_id text,
  ADD COLUMN signature_algorithm text,
  ADD COLUMN signature text,
  ADD COLUMN signature_issued_at timestamptz,
  ADD CONSTRAINT analysis_jobs_signature_complete CHECK (
    (signing_key_id IS NULL AND signature_algorithm IS NULL AND signature IS NULL) OR
    (signing_key_id IS NOT NULL AND signature_algorithm='Ed25519' AND signature IS NOT NULL)
  );

ALTER TABLE agents
  ADD COLUMN contract_version text NOT NULL DEFAULT '1.0',
  ADD COLUMN capability_schema_version text NOT NULL DEFAULT '1.0',
  ADD COLUMN signing_key_id text,
  ADD COLUMN certificate_rotation_status text NOT NULL DEFAULT 'IDLE' CHECK(certificate_rotation_status IN ('IDLE','REQUESTED','ISSUED','GRACE_PERIOD','FAILED'));

ALTER TABLE organizations
  ADD COLUMN require_signed_jobs boolean NOT NULL DEFAULT false;

INSERT INTO agent_certificates(organization_id,agent_id,serial_number,fingerprint,not_before,not_after,status,issued_at)
SELECT organization_id,id,certificate_serial,identity_fingerprint,registered_at,certificate_expires_at,
       CASE WHEN certificate_expires_at <= now() THEN 'EXPIRED'::agent_certificate_status ELSE 'ACTIVE'::agent_certificate_status END,
       registered_at
FROM agents
WHERE certificate_serial IS NOT NULL AND certificate_expires_at IS NOT NULL AND identity_fingerprint <> 'pending';
