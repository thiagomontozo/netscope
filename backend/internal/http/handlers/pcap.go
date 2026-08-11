package handlers

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/pcap"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
)

type PCAP struct {
	Pool    *pgxpool.Pool
	Storage storage.ObjectStorage
	Policy  interface {
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}

func (h PCAP) allowed(w http.ResponseWriter, r *http.Request, permission string) bool {
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), permission)
	if err != nil || !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "the required PCAP permission is not granted")
		return false
	}
	return true
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	c.count += int64(n)
	return n, err
}
func (h PCAP) Upload(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "pcap.upload") {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<30)
	file, header, err := r.FormFile("file")
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "PCAP_UPLOAD_INVALID", "a PCAP file is required")
		return
	}
	defer file.Close()
	buffered := bufio.NewReader(file)
	magic, peekErr := buffered.Peek(4)
	if peekErr != nil {
		middleware.WriteError(w, r, http.StatusBadRequest, "PCAP_UPLOAD_INVALID", "PCAP header is missing")
		return
	}
	signature := hex.EncodeToString(magic)
	validMagic := map[string]bool{"d4c3b2a1": true, "a1b2c3d4": true, "4d3cb2a1": true, "a1b23c4d": true, "0a0d0d0a": true}
	if !validMagic[signature] {
		middleware.WriteError(w, r, http.StatusBadRequest, "PCAP_FORMAT_INVALID", "file is not a recognized PCAP or PCAPNG artifact")
		return
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "PCAP_UPLOAD_FAILED", "artifact key could not be generated")
		return
	}
	org := middleware.OrganizationID(r.Context())
	key := fmt.Sprintf("%s/pcap/%s.pcap", org, hex.EncodeToString(random))
	hash := sha256.New()
	counter := &countingReader{reader: io.TeeReader(buffered, hash)}
	if err = h.Storage.Put(r.Context(), key, counter); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "PCAP_STORAGE_FAILED", "PCAP could not be stored")
		return
	}
	checksum := hex.EncodeToString(hash.Sum(nil))
	retentionDays := int(pcap.DefaultRetention / (24 * time.Hour))
	_ = h.Pool.QueryRow(r.Context(), `SELECT coalesce((SELECT retention_days FROM retention_policies WHERE organization_id=$1 AND category='PCAP' AND enabled),$2)`, org, retentionDays).Scan(&retentionDays)
	expires := time.Now().UTC().Add(time.Duration(retentionDays) * 24 * time.Hour)
	var id domain.ID
	err = h.Pool.QueryRow(r.Context(), `INSERT INTO pcap_artifacts(organization_id,uploaded_by,storage_key,original_filename,content_length,checksum,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id::text`, org, middleware.UserID(r.Context()), key, header.Filename, counter.count, checksum, expires).Scan(&id)
	if err != nil {
		_ = h.Storage.Delete(r.Context(), key)
		middleware.WriteError(w, r, http.StatusInternalServerError, "PCAP_UPLOAD_FAILED", "PCAP metadata could not be saved")
		return
	}
	_, _ = h.Pool.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome,metadata) VALUES($1,$2,'pcap.uploaded','pcap',$3,$4,'success',jsonb_build_object('bytes',$5,'checksum',$6))`, org, middleware.UserID(r.Context()), id, middleware.RequestIDFrom(r.Context()), counter.count, checksum)
	middleware.JSON(w, http.StatusCreated, map[string]any{"data": map[string]any{"id": id, "checksum": checksum, "expiresAt": expires}})
}
func (h PCAP) Download(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "pcap.download") {
		return
	}
	org := middleware.OrganizationID(r.Context())
	id := domain.ID(chi.URLParam(r, "id"))
	var key string
	err := h.Pool.QueryRow(r.Context(), `SELECT storage_key FROM pcap_artifacts WHERE organization_id=$1 AND id=$2 AND deleted_at IS NULL AND expires_at>now()`, org, id).Scan(&key)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "PCAP_NOT_FOUND", "PCAP is missing, expired or deleted")
		return
	}
	reader, err := h.Storage.Open(r.Context(), key)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "PCAP_ARTIFACT_MISSING", "PCAP artifact is unavailable")
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="netscope-capture.pcap"`)
	_, _ = io.Copy(w, reader)
}
func (h PCAP) Delete(w http.ResponseWriter, r *http.Request) {
	if !h.allowed(w, r, "pcap.delete") {
		return
	}
	org := middleware.OrganizationID(r.Context())
	id := domain.ID(chi.URLParam(r, "id"))
	var key string
	err := h.Pool.QueryRow(r.Context(), `SELECT storage_key FROM pcap_artifacts WHERE organization_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, org, id).Scan(&key)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "PCAP_NOT_FOUND", "PCAP was not found in this organization")
		return
	}
	if err = h.Storage.Delete(r.Context(), key); err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "PCAP_DELETE_FAILED", "PCAP artifact could not be deleted")
		return
	}
	_, err = h.Pool.Exec(r.Context(), `UPDATE pcap_artifacts SET deleted_at=now() WHERE organization_id=$1 AND id=$2`, org, id)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "PCAP_DELETE_FAILED", "PCAP deletion could not be recorded")
		return
	}
	_, _ = h.Pool.Exec(r.Context(), `INSERT INTO audit_events(organization_id,actor_user_id,event_type,resource_type,resource_id,request_id,outcome) VALUES($1,$2,'pcap.deleted','pcap',$3,$4,'success')`, org, middleware.UserID(r.Context()), id, middleware.RequestIDFrom(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}
