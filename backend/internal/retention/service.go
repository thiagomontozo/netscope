package retention

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/netscope/backend/internal/storage"
)

type Service struct {
	Pool    *pgxpool.Pool
	Storage storage.ObjectStorage
}

func (s Service) RunOnce(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx, `SELECT id,organization_id,storage_key FROM pcap_artifacts WHERE deleted_at IS NULL AND expires_at<=now() ORDER BY expires_at LIMIT 100`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type expired struct{ id, org, key string }
	items := []expired{}
	for rows.Next() {
		var item expired
		if err = rows.Scan(&item.id, &item.org, &item.key); err != nil {
			return err
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	var failures []error
	for _, item := range items {
		if err = s.Storage.Delete(ctx, item.key); err != nil {
			failures = append(failures, err)
			continue
		}
		_, err = s.Pool.Exec(ctx, `WITH changed AS (UPDATE pcap_artifacts SET deleted_at=now() WHERE organization_id=$1 AND id=$2 AND deleted_at IS NULL RETURNING id) INSERT INTO audit_events(organization_id,event_type,resource_type,resource_id,outcome,metadata) SELECT $1,'pcap.retention_deleted','pcap',id::text,'success',jsonb_build_object('policy','expiry') FROM changed`, item.org, item.id)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
