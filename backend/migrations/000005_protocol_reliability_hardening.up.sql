-- NetScope v0.2.1: explicit certificate rotation terminal states and
-- transactional Artifact -> Evidence -> Observation relationships.
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_certificate_rotation_status_check;
ALTER TABLE agents ADD CONSTRAINT agents_certificate_rotation_status_check CHECK (
  certificate_rotation_status IN ('IDLE','REQUESTED','ISSUED','PENDING_CONFIRMATION','ACTIVATING','COMPLETED','FAILED','ROLLED_BACK')
);
ALTER TABLE agents
  ADD COLUMN certificate_not_before timestamptz,
  ADD COLUMN previous_certificate_fingerprint text CHECK(previous_certificate_fingerprint IS NULL OR previous_certificate_fingerprint ~ '^[a-f0-9]{64}$'),
  ADD COLUMN last_certificate_rotation_at timestamptz;
UPDATE agents a SET certificate_not_before=c.not_before
FROM agent_certificates c
WHERE c.organization_id=a.organization_id AND c.agent_id=a.id AND c.status='ACTIVE';

ALTER TABLE evidence ADD COLUMN artifact_id uuid REFERENCES artifacts(id) ON DELETE RESTRICT;
ALTER TABLE observations ADD COLUMN evidence_id uuid REFERENCES evidence(id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX evidence_artifact_unique_idx
  ON evidence(organization_id,artifact_id) WHERE artifact_id IS NOT NULL;
CREATE UNIQUE INDEX observations_evidence_job_unique_idx
  ON observations(organization_id,evidence_id,job_id) WHERE evidence_id IS NOT NULL;
CREATE INDEX evidence_artifact_idx ON evidence(organization_id,artifact_id);
CREATE INDEX observations_evidence_idx ON observations(organization_id,evidence_id);
