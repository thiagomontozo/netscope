package handlers

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/http/middleware"
	"github.com/thiagomontozo/netscope/backend/internal/vulnerabilities"
	"net/http"
	"time"
)

type Enrichment struct {
	Pool   *pgxpool.Pool
	NVD    vulnerabilities.VulnerabilityEnrichmentProvider
	KEV    vulnerabilities.KnownExploitedProvider
	Policy interface {
		Has(context.Context, domain.ID, domain.ID, string) (bool, error)
	}
}

func (h Enrichment) Run(w http.ResponseWriter, r *http.Request) {
	ok, err := h.Policy.Has(r.Context(), middleware.OrganizationID(r.Context()), middleware.UserID(r.Context()), "vulnerability.run")
	if err != nil || !ok {
		middleware.WriteError(w, r, http.StatusForbidden, "PERMISSION_DENIED", "vulnerability enrichment permission is not granted")
		return
	}
	org, id := middleware.OrganizationID(r.Context()), domain.ID(chi.URLParam(r, "id"))
	var cve string
	err = h.Pool.QueryRow(r.Context(), `SELECT cve FROM vulnerabilities WHERE organization_id=$1 AND id=$2 AND cve IS NOT NULL`, org, id).Scan(&cve)
	if err != nil {
		middleware.WriteError(w, r, http.StatusNotFound, "CVE_NOT_FOUND", "vulnerability has no CVE in this organization")
		return
	}
	nvd, err := h.NVD.Lookup(r.Context(), cve)
	if err != nil {
		middleware.WriteError(w, r, http.StatusBadGateway, "NVD_ENRICHMENT_FAILED", "NVD enrichment is temporarily unavailable")
		return
	}
	kev, kevErr := h.KEV.Lookup(r.Context(), cve)
	var knownExploited any = kev.KnownExploited
	if kevErr != nil {
		knownExploited = nil
	}
	cvss, _ := json.Marshal(nvd.CVSS)
	references, _ := json.Marshal(nvd.References)
	_, err = h.Pool.Exec(r.Context(), `INSERT INTO vulnerability_enrichments(vulnerability_id,provider,cve,description,cvss,reference_urls,known_exploited,date_added,required_action,due_date,fetched_at,expires_at) VALUES($1,'NVD_CISA',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(vulnerability_id,provider) DO UPDATE SET description=excluded.description,cvss=excluded.cvss,reference_urls=excluded.reference_urls,known_exploited=excluded.known_exploited,date_added=excluded.date_added,required_action=excluded.required_action,due_date=excluded.due_date,fetched_at=excluded.fetched_at,expires_at=excluded.expires_at`, id, cve, nvd.Description, cvss, references, knownExploited, kev.DateAdded, kev.RequiredAction, kev.DueDate, nvd.FetchedAt, nvd.ExpiresAt)
	if err != nil {
		middleware.WriteError(w, r, http.StatusInternalServerError, "ENRICHMENT_SAVE_FAILED", "enrichment could not be cached")
		return
	}
	response := map[string]any{"cve": cve, "description": nvd.Description, "cvss": nvd.CVSS, "references": nvd.References, "knownExploited": kev.KnownExploited, "fetchedAt": time.Now().UTC()}
	if kevErr != nil {
		response["knownExploitedStatus"] = "INCONCLUSIVE"
	}
	middleware.JSON(w, http.StatusOK, map[string]any{"data": response})
}
