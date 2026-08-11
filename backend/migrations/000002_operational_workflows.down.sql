DROP INDEX IF EXISTS pcap_retention_idx;
DROP TABLE IF EXISTS maintenance_windows;
DROP INDEX IF EXISTS mfa_challenges_active_idx;
ALTER TABLE agent_enrollment_tokens DROP COLUMN IF EXISTS requested_name;
ALTER TABLE agents DROP COLUMN IF EXISTS certificate_expires_at;
ALTER TABLE agents DROP COLUMN IF EXISTS certificate_serial;
DROP TABLE IF EXISTS organization_module_settings;
