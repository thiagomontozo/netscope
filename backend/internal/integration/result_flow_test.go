package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/agents"
	"github.com/thiagomontozo/netscope/backend/internal/artifacts"
	"github.com/thiagomontozo/netscope/backend/internal/database"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/handlers"
	appmw "github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
)

const (
	testOrg   = domain.ID("22222222-2222-4222-8222-222222222222")
	testAgent = domain.ID("11111111-1111-4111-8111-111111111111")
	testUser  = "55555555-5555-4555-8555-555555555555"
	testScope = "44444444-4444-4444-8444-444444444444"
	testAsset = "66666666-6666-4666-8666-666666666666"
)

type fixedAgentStore struct{}

func (fixedAgentStore) ValidateAgentFingerprint(context.Context, string) (domain.ID, domain.ID, error) {
	return testOrg, testAgent, nil
}
func (fixedAgentStore) ValidateRotatingAgentFingerprint(context.Context, string) (domain.ID, domain.ID, error) {
	return testOrg, testAgent, nil
}

func TestArtifactEvidenceObservationTransactionAndIdempotency(t *testing.T) {
	databaseURL := os.Getenv("NETSCOPE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("NETSCOPE_TEST_DATABASE_URL is only configured by safe CI integration validation")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	seed(t, pool)

	handler := handlers.Agent{Enrollment: agents.EnrollmentService{Pool: pool}}
	objectStorage, err := storage.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tokens := artifacts.TokenManager{Key: []byte("TEST ONLY 32-byte artifact token key material"), TTL: time.Minute}
	artifactHandler := handlers.AgentArtifacts{Pool: pool, Storage: objectStorage, Tokens: tokens, MaxUploadBytes: 1024, MaxDownloadBytes: 1024, TempDir: t.TempDir()}
	router := chi.NewRouter()
	router.Use(appmw.AgentIdentity(fixedAgentStore{}))
	router.Post("/jobs/{id}/result", handler.Result)
	router.Put("/artifacts/{id}/content", artifactHandler.Upload)

	artifactContent := []byte("TEST ONLY synthetic artifact output\n")
	digest := sha256.Sum256(artifactContent)
	checksum := hex.EncodeToString(digest[:])
	jobID := "33333333-3333-4333-8333-333333333333"
	artifactID := "77777777-7777-4777-8777-777777777777"
	evidenceID := "88888888-8888-4888-8888-888888888888"
	insertJobAndArtifact(t, pool, jobID, artifactID, "PENDING", checksum, int64(len(artifactContent)), testOrg)
	claims := artifacts.TransferClaims{ArtifactID: artifactID, OrganizationID: string(testOrg), AgentID: string(testAgent), JobID: jobID, Purpose: artifacts.PurposeUpload}
	token, err := tokens.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}
	if status := uploadArtifact(t, router, jobID, artifactID, token, checksum, artifactContent); status != http.StatusNoContent {
		t.Fatalf("artifact upload returned %d", status)
	}
	payload := resultPayload(jobID, artifactID, evidenceID, checksum, int64(len(artifactContent)))
	if status := postResult(t, router, jobID, payload); status != http.StatusNoContent {
		t.Fatalf("happy path returned %d", status)
	}
	assertCounts(t, pool, jobID, 1, 1, 1, "SUCCEEDED")
	if status := postResult(t, router, jobID, payload); status != http.StatusNoContent {
		t.Fatalf("idempotent retry returned %d", status)
	}
	assertCounts(t, pool, jobID, 1, 1, 1, "SUCCEEDED")

	failedJob := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	failedArtifact := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	failedEvidence := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	insertJobAndArtifact(t, pool, failedJob, failedArtifact, "FAILED", checksum, int64(len(artifactContent)), testOrg)
	if status := postResult(t, router, failedJob, resultPayload(failedJob, failedArtifact, failedEvidence, checksum, int64(len(artifactContent)))); status != http.StatusBadRequest {
		t.Fatalf("failed artifact returned %d", status)
	}
	assertCounts(t, pool, failedJob, 0, 0, 0, "RUNNING")

	crossJob := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	crossArtifact := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	crossEvidence := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	insertJobAndArtifact(t, pool, crossJob, crossArtifact, "AVAILABLE", checksum, int64(len(artifactContent)), "99999999-9999-4999-8999-999999999999")
	if status := postResult(t, router, crossJob, resultPayload(crossJob, crossArtifact, crossEvidence, checksum, int64(len(artifactContent)))); status != http.StatusBadRequest {
		t.Fatalf("cross-organization artifact returned %d", status)
	}
	assertCounts(t, pool, crossJob, 0, 0, 0, "RUNNING")

	checksumJob := "12121212-1212-4212-8212-121212121212"
	checksumArtifact := "13131313-1313-4313-8313-131313131313"
	insertJobAndArtifact(t, pool, checksumJob, checksumArtifact, "PENDING", checksum, int64(len(artifactContent)), testOrg)
	checksumClaims := artifacts.TransferClaims{ArtifactID: checksumArtifact, OrganizationID: string(testOrg), AgentID: string(testAgent), JobID: checksumJob, Purpose: artifacts.PurposeUpload}
	checksumToken, _ := tokens.Issue(checksumClaims)
	tampered := append([]byte(nil), artifactContent...)
	tampered[0] = 'X'
	if status := uploadArtifact(t, router, checksumJob, checksumArtifact, checksumToken, checksum, tampered); status != http.StatusUnprocessableEntity {
		t.Fatalf("checksum mismatch upload returned %d", status)
	}
	var artifactStatus string
	var checksumAudits int
	if err := pool.QueryRow(context.Background(), `SELECT status::text,(SELECT count(*) FROM audit_events WHERE resource_id=$1 AND event_type='artifact.checksum_failed') FROM artifacts WHERE id=$1`, checksumArtifact).Scan(&artifactStatus, &checksumAudits); err != nil || artifactStatus != "FAILED" || checksumAudits != 1 {
		t.Fatalf("checksum failure state=%s audits=%d err=%v", artifactStatus, checksumAudits, err)
	}
	assertCounts(t, pool, checksumJob, 0, 0, 0, "RUNNING")

	transactionJob := "14141414-1414-4414-8414-141414141414"
	transactionArtifact := "15151515-1515-4515-8515-151515151515"
	transactionEvidence := "16161616-1616-4616-8616-161616161616"
	insertJobAndArtifact(t, pool, transactionJob, transactionArtifact, "AVAILABLE", checksum, int64(len(artifactContent)), testOrg)
	invalidRelationship := resultPayload(transactionJob, transactionArtifact, transactionEvidence, checksum, int64(len(artifactContent)))
	var decoded map[string]any
	_ = json.Unmarshal(invalidRelationship, &decoded)
	decoded["observations"].([]any)[0].(map[string]any)["evidenceId"] = "17171717-1717-4717-8717-171717171717"
	invalidRelationship, _ = json.Marshal(decoded)
	if status := postResult(t, router, transactionJob, invalidRelationship); status != http.StatusBadRequest {
		t.Fatalf("transactional relationship failure returned %d", status)
	}
	assertCounts(t, pool, transactionJob, 0, 0, 0, "RUNNING")
}

func TestCertificateRotationSuccessAndRollback(t *testing.T) {
	databaseURL := os.Getenv("NETSCOPE_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("NETSCOPE_TEST_DATABASE_URL is only configured by safe CI integration validation")
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	seed(t, pool)
	ca := ephemeralControlPlaneCA(t)
	service := agents.RotationService{Pool: pool, CA: ca, Policy: agents.DefaultCertificatePolicy()}

	csrB, _ := testCSR(t)
	if bytes.Contains([]byte(csrB), []byte("PRIVATE KEY")) {
		t.Fatal("Control Plane request contained private key B")
	}
	issued, err := service.Request(context.Background(), testOrg, testAgent, csrB)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	certificateB, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rotationHandler := handlers.Agent{Rotation: service}
	rotationRouter := chi.NewRouter()
	rotationRouter.Use(appmw.RotatingAgentIdentity(database.ControlPlane{Pool: pool}))
	rotationRouter.Post("/identity/rotate/confirm", rotationHandler.ConfirmIdentityRotation)
	confirmBody, _ := json.Marshal(map[string]string{"certificateId": string(issued.CertificateID)})
	confirmRequest := httptest.NewRequest(http.MethodPost, "/identity/rotate/confirm", bytes.NewReader(confirmBody))
	confirmRequest.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificateB}, VerifiedChains: [][]*x509.Certificate{{certificateB}}}
	confirmRecorder := httptest.NewRecorder()
	rotationRouter.ServeHTTP(confirmRecorder, confirmRequest)
	if confirmRecorder.Code != http.StatusNoContent {
		t.Fatalf("new certificate confirmation returned %d: %s", confirmRecorder.Code, confirmRecorder.Body.String())
	}
	var currentFingerprint, rotationStatus, newStatus, oldStatus string
	if err := pool.QueryRow(context.Background(), `SELECT a.identity_fingerprint,a.certificate_rotation_status,n.status::text,o.status::text FROM agents a JOIN agent_certificates n ON n.organization_id=a.organization_id AND n.agent_id=a.id AND n.fingerprint=$3 JOIN agent_certificates o ON o.organization_id=a.organization_id AND o.agent_id=a.id AND o.fingerprint=repeat('a',64) WHERE a.organization_id=$1 AND a.id=$2`, testOrg, testAgent, issued.Fingerprint).Scan(&currentFingerprint, &rotationStatus, &newStatus, &oldStatus); err != nil {
		t.Fatal(err)
	}
	if currentFingerprint != issued.Fingerprint || rotationStatus != "COMPLETED" || newStatus != "ACTIVE" || oldStatus != "SUPERSEDED" {
		t.Fatalf("unexpected completed rotation state %s %s %s %s", currentFingerprint, rotationStatus, newStatus, oldStatus)
	}

	csrC, _ := testCSR(t)
	pending, err := service.Request(context.Background(), testOrg, testAgent, csrC)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Rollback(context.Background(), testOrg, testAgent, pending.CertificateID); err != nil {
		t.Fatal(err)
	}
	var pendingStatus string
	if err := pool.QueryRow(context.Background(), `SELECT a.certificate_rotation_status,c.status::text FROM agents a JOIN agent_certificates c ON c.organization_id=a.organization_id AND c.agent_id=a.id WHERE a.organization_id=$1 AND a.id=$2 AND c.id=$3`, testOrg, testAgent, pending.CertificateID).Scan(&rotationStatus, &pendingStatus); err != nil {
		t.Fatal(err)
	}
	if rotationStatus != "ROLLED_BACK" || pendingStatus != "REVOKED" {
		t.Fatalf("unexpected rollback state %s %s", rotationStatus, pendingStatus)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE agents SET status='REVOKED' WHERE organization_id=$1 AND id=$2`, testOrg, testAgent); err != nil {
		t.Fatal(err)
	}
	revokedCSR, _ := testCSR(t)
	if _, err := service.Request(context.Background(), testOrg, testAgent, revokedCSR); err == nil {
		t.Fatal("revoked Agent started a certificate rotation")
	}
}

func seed(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events; DELETE FROM agent_result_receipts; UPDATE evidence SET observation_id=NULL; UPDATE observations SET evidence_id=NULL; DELETE FROM observations; DELETE FROM evidence; DELETE FROM artifacts; DELETE FROM analysis_jobs; DELETE FROM authorized_scopes; DELETE FROM assets; DELETE FROM agent_certificates; DELETE FROM agents; DELETE FROM users; DELETE FROM organizations`)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations(id,name,slug) VALUES($1,'TEST ONLY Org','test-only-org'),('99999999-9999-4999-8999-999999999999','TEST ONLY Other','test-only-other')`, []any{testOrg}},
		{`INSERT INTO users(id,organization_id,name,email,password_hash) VALUES($1,$2,'Test','test@example.invalid','unused')`, []any{testUser, testOrg}},
		{`INSERT INTO authorized_scopes(id,organization_id,type,value,environment,status,valid_from,valid_until) VALUES($1,$2,'HOSTNAME','fixture.test.invalid','INTERNAL','APPROVED',now()-interval '1 hour',now()+interval '1 hour')`, []any{testScope, testOrg}},
		{`INSERT INTO assets(id,organization_id,name,type,environment,criticality) VALUES($1,$2,'fixture','HOST','INTERNAL','LOW')`, []any{testAsset, testOrg}},
		{`INSERT INTO agents(id,organization_id,name,hostname,os,arch,version,status,identity_fingerprint,protocol_version,compatibility_status,certificate_serial,certificate_expires_at) VALUES($1,$2,'fixture','fixture','test','amd64','0.2.1-experimental','ONLINE',repeat('a',64),'1.0','COMPATIBLE','test-serial',now()+interval '1 day')`, []any{testAgent, testOrg}},
		{`INSERT INTO agent_certificates(organization_id,agent_id,serial_number,fingerprint,not_before,not_after,status) VALUES($1,$2,'test-serial',repeat('a',64),now()-interval '1 hour',now()+interval '1 day','ACTIVE')`, []any{testOrg, testAgent}},
		{`INSERT INTO module_definitions(id,name,version,category,risk_class,supported_environments,required_capabilities,default_timeout_seconds,input_schema,result_schema) VALUES('mock.safe','Mock safe','0.2.1','test','PASSIVE','{INTERNAL}','{}',30,'{"type":"object"}','{"type":"object"}') ON CONFLICT(id) DO NOTHING`, nil},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func ephemeralControlPlaneCA(t *testing.T) *agents.CertificateAuthority {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TEST ONLY Control Plane CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	return &agents.CertificateAuthority{Certificate: certificate, PrivateKey: key, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func testCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "TEST ONLY Agent B"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func insertJobAndArtifact(t *testing.T, pool *pgxpool.Pool, jobID, artifactID, status, checksum string, size int64, artifactOrg domain.ID) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO analysis_jobs(id,organization_id,module_id,asset_id,scope_id,agent_id,requested_by,parameters,normalized_target,risk_class,status,started_at,timeout_at) VALUES($1,$2,'mock.safe',$3,$4,$5,$6,'{}','fixture.test.invalid','PASSIVE','RUNNING',now()-interval '1 minute',now()+interval '10 minutes')`, jobID, testOrg, testAsset, testScope, testAgent, testUser)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(context.Background(), `INSERT INTO artifacts(id,organization_id,job_id,type,direction,content_type,storage_key,size_bytes,sha256,status,uploaded_by_agent_id,verified_at) VALUES($1::uuid,$2::uuid,CASE WHEN $2::uuid=$3::uuid THEN $4::uuid ELSE NULL END,'JOB_OUTPUT','AGENT_TO_CONTROL_PLANE','text/plain','organizations/'||$2::text||'/artifacts/'||$1::text,$5::bigint,$6::text,$7::artifact_status,CASE WHEN $2::uuid=$3::uuid THEN $8::uuid ELSE NULL END,CASE WHEN $7::text='AVAILABLE' THEN now() END)`, artifactID, artifactOrg, testOrg, jobID, size, checksum, status, testAgent)
	if err != nil {
		t.Fatal(err)
	}
}

func resultPayload(jobID, artifactID, evidenceID, checksum string, size int64) []byte {
	now := time.Now().UTC().Truncate(time.Millisecond)
	value := map[string]any{"protocolVersion": "1.0", "resultIdentity": "result-" + jobID, "resultVersion": 1, "jobId": jobID, "agentId": testAgent, "moduleId": "mock.safe", "status": "SUCCEEDED", "startedAt": now.Add(-time.Second), "completedAt": now, "summary": "TEST ONLY synthetic result", "observations": []any{map[string]any{"assetId": testAsset, "evidenceId": evidenceID, "category": "test.synthetic", "status": "INFORMATIONAL", "severity": "INFORMATIONAL", "confidence": "HIGH", "title": "Synthetic observation", "summary": "Synthetic summary", "meaning": "Test only", "impact": "None", "suggestedAction": "None", "observedAt": now}}, "metrics": []any{}, "warnings": []any{}, "evidenceManifest": []any{map[string]any{"evidenceId": evidenceID, "artifactId": artifactID, "source": "mock.safe", "contentType": "text/plain", "summary": "Synthetic artifact evidence", "structuredData": map[string]any{"synthetic": true}, "sha256": checksum, "sizeBytes": size, "artifactKind": "RAW_OUTPUT"}}, "truncated": false}
	encoded, _ := json.Marshal(value)
	return encoded
}

func postResult(t *testing.T, handler http.Handler, jobID string, payload []byte) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/jobs/"+jobID+"/result", bytes.NewReader(payload))
	certificate := &x509.Certificate{Raw: []byte("TEST ONLY agent certificate")}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func uploadArtifact(t *testing.T, handler http.Handler, jobID, artifactID, token, checksum string, content []byte) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/artifacts/"+artifactID+"/content?jobId="+jobID, bytes.NewReader(content))
	request.Header.Set("Authorization", "Artifact "+token)
	request.Header.Set("X-NetScope-Artifact-SHA256", checksum)
	certificate := &x509.Certificate{Raw: []byte("TEST ONLY agent certificate")}
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func assertCounts(t *testing.T, pool *pgxpool.Pool, jobID string, evidence, observations, receipts int, status string) {
	t.Helper()
	var gotEvidence, gotObservations, gotReceipts int
	var gotStatus string
	err := pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM evidence WHERE job_id=$1),(SELECT count(*) FROM observations WHERE job_id=$1),(SELECT count(*) FROM agent_result_receipts WHERE job_id=$1),(SELECT status::text FROM analysis_jobs WHERE id=$1)`, jobID).Scan(&gotEvidence, &gotObservations, &gotReceipts, &gotStatus)
	if err != nil || gotEvidence != evidence || gotObservations != observations || gotReceipts != receipts || gotStatus != status {
		t.Fatalf("state mismatch evidence=%d observations=%d receipts=%d status=%s err=%v", gotEvidence, gotObservations, gotReceipts, gotStatus, err)
	}
}
