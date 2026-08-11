CREATE TABLE organization_module_settings (
  organization_id uuid NOT NULL REFERENCES organizations(id),
  module_id text NOT NULL REFERENCES module_definitions(id),
  enabled boolean NOT NULL,
  updated_by uuid NOT NULL REFERENCES users(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(organization_id,module_id)
);

ALTER TABLE agents ADD COLUMN certificate_serial text;
ALTER TABLE agents ADD COLUMN certificate_expires_at timestamptz;
ALTER TABLE agent_enrollment_tokens ADD COLUMN requested_name text;
CREATE INDEX mfa_challenges_active_idx ON mfa_login_challenges(token_hash,expires_at) WHERE used_at IS NULL;
CREATE INDEX pcap_retention_idx ON pcap_artifacts(organization_id,expires_at) WHERE deleted_at IS NULL;
CREATE TABLE maintenance_windows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  starts_at timestamptz NOT NULL,
  ends_at timestamptz NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid NOT NULL REFERENCES users(id),
  CHECK(ends_at > starts_at)
);
CREATE INDEX maintenance_windows_active_idx ON maintenance_windows(organization_id,starts_at,ends_at) WHERE enabled;
