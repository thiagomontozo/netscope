package reports

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
)

type Summary struct {
	Title            string
	GeneratedAt      time.Time
	Assets           int
	OpenFindings     int
	CriticalFindings int
	AgentsOnline     int
	Inconclusive     int
	Disclaimer       string
}
type Service struct {
	Pool    *pgxpool.Pool
	Storage storage.ObjectStorage
}

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>{{.Title}}</title><style>body{font-family:system-ui;color:#172034;max-width:900px;margin:40px auto;padding:0 24px}h1{border-bottom:2px solid #3765d6;padding-bottom:12px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.card{border:1px solid #dbe3ee;border-radius:10px;padding:16px}.value{font-size:28px;font-weight:700}.note{background:#f7f9fc;padding:16px;border-left:4px solid #9a6817;margin-top:24px}</style></head><body><h1>{{.Title}}</h1><p>Generated {{.GeneratedAt.UTC.Format "2006-01-02 15:04 UTC"}}</p><div class="grid"><div class="card"><div class="value">{{.Assets}}</div>Assets</div><div class="card"><div class="value">{{.AgentsOnline}}</div>Agents online</div><div class="card"><div class="value">{{.OpenFindings}}</div>Open findings</div><div class="card"><div class="value">{{.CriticalFindings}}</div>Critical findings</div><div class="card"><div class="value">{{.Inconclusive}}</div>Inconclusive observations</div></div><div class="note">{{.Disclaimer}}</div></body></html>`))

func (s Service) Create(ctx context.Context, org, user domain.ID, reportType Type, title string) (domain.ID, error) {
	summary := Summary{Title: title, GeneratedAt: time.Now().UTC(), Disclaimer: "Severity is not the same as risk. Vulnerability detection is not proof of compromise. Inconclusive is a valid result."}
	err := s.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM assets WHERE organization_id=$1),(SELECT count(*) FROM findings WHERE organization_id=$1 AND status IN ('OPEN','ACKNOWLEDGED')),(SELECT count(*) FROM findings WHERE organization_id=$1 AND status IN ('OPEN','ACKNOWLEDGED') AND priority='CRITICAL'),(SELECT count(*) FROM agents WHERE organization_id=$1 AND status='ONLINE'),(SELECT count(*) FROM observations WHERE organization_id=$1 AND status='INCONCLUSIVE')`, org).Scan(&summary.Assets, &summary.OpenFindings, &summary.CriticalFindings, &summary.AgentsOnline, &summary.Inconclusive)
	if err != nil {
		return "", err
	}
	var content bytes.Buffer
	if err = reportTemplate.Execute(&content, summary); err != nil {
		return "", err
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return "", err
	}
	key := fmt.Sprintf("%s/reports/%s.html", org, hex.EncodeToString(random))
	if err = s.Storage.Put(ctx, key, &content); err != nil {
		return "", err
	}
	var id domain.ID
	err = s.Pool.QueryRow(ctx, `INSERT INTO reports(organization_id,type,title,status,storage_key,created_by,completed_at) VALUES($1,$2,$3,'COMPLETED',$4,$5,now()) RETURNING id::text`, org, reportType, title, key, user).Scan(&id)
	if err != nil {
		_ = s.Storage.Delete(ctx, key)
		return "", err
	}
	return id, nil
}
func (s Service) Open(ctx context.Context, org, id domain.ID) (io.ReadCloser, string, error) {
	var key, title string
	err := s.Pool.QueryRow(ctx, `SELECT storage_key,title FROM reports WHERE organization_id=$1 AND id=$2 AND status='COMPLETED'`, org, id).Scan(&key, &title)
	if err != nil {
		return nil, "", err
	}
	reader, err := s.Storage.Open(ctx, key)
	return reader, title, err
}
