ALTER TABLE organizations DROP COLUMN IF EXISTS require_signed_jobs;
ALTER TABLE agents DROP COLUMN IF EXISTS certificate_rotation_status, DROP COLUMN IF EXISTS signing_key_id, DROP COLUMN IF EXISTS capability_schema_version, DROP COLUMN IF EXISTS contract_version;
ALTER TABLE analysis_jobs DROP CONSTRAINT IF EXISTS analysis_jobs_signature_complete;
ALTER TABLE analysis_jobs DROP COLUMN IF EXISTS signature_issued_at, DROP COLUMN IF EXISTS signature, DROP COLUMN IF EXISTS signature_algorithm, DROP COLUMN IF EXISTS signing_key_id;
DROP TABLE IF EXISTS artifacts;
DROP TABLE IF EXISTS agent_certificates;
DROP TYPE IF EXISTS artifact_status;
DROP TYPE IF EXISTS artifact_direction;
DROP TYPE IF EXISTS agent_certificate_status;
