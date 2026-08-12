DROP INDEX IF EXISTS observations_evidence_idx;
DROP INDEX IF EXISTS evidence_artifact_idx;
DROP INDEX IF EXISTS observations_evidence_job_unique_idx;
DROP INDEX IF EXISTS evidence_artifact_unique_idx;
ALTER TABLE observations DROP COLUMN IF EXISTS evidence_id;
ALTER TABLE evidence DROP COLUMN IF EXISTS artifact_id;
ALTER TABLE agents DROP COLUMN IF EXISTS last_certificate_rotation_at, DROP COLUMN IF EXISTS previous_certificate_fingerprint, DROP COLUMN IF EXISTS certificate_not_before;
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_certificate_rotation_status_check;
UPDATE agents SET certificate_rotation_status=CASE certificate_rotation_status
  WHEN 'COMPLETED' THEN 'GRACE_PERIOD'
  WHEN 'ROLLED_BACK' THEN 'FAILED'
  WHEN 'PENDING_CONFIRMATION' THEN 'ISSUED'
  WHEN 'ACTIVATING' THEN 'ISSUED'
  ELSE certificate_rotation_status END;
ALTER TABLE agents ADD CONSTRAINT agents_certificate_rotation_status_check CHECK (
  certificate_rotation_status IN ('IDLE','REQUESTED','ISSUED','GRACE_PERIOD','FAILED')
);
