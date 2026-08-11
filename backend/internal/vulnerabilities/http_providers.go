package vulnerabilities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type NVDProvider struct {
	Client   *http.Client
	BaseURL  string
	APIKey   string
	CacheTTL time.Duration
}
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Metrics struct {
				V31 []struct {
					CVSS struct {
						Version   string  `json:"version"`
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				V30 []struct {
					CVSS struct {
						Version   string  `json:"version"`
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func (p NVDProvider) Lookup(ctx context.Context, cve string) (Enrichment, error) {
	if !strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
		return Enrichment{}, errors.New("CVE identifier is invalid")
	}
	base := p.BaseURL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	target, err := url.Parse(base)
	if err != nil {
		return Enrichment{}, err
	}
	query := target.Query()
	query.Set("cveId", strings.ToUpper(cve))
	target.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Enrichment{}, err
	}
	request.Header.Set("Accept", "application/json")
	if p.APIKey != "" {
		request.Header.Set("apiKey", p.APIKey)
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return Enrichment{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Enrichment{}, fmt.Errorf("NVD returned status %d", response.StatusCode)
	}
	var payload nvdResponse
	if err = json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&payload); err != nil {
		return Enrichment{}, err
	}
	if len(payload.Vulnerabilities) != 1 {
		return Enrichment{}, errors.New("NVD returned no unique CVE")
	}
	record := payload.Vulnerabilities[0].CVE
	description := ""
	for _, item := range record.Descriptions {
		if item.Lang == "en" {
			description = item.Value
			break
		}
	}
	references := make([]string, 0, len(record.References))
	for _, item := range record.References {
		references = append(references, item.URL)
	}
	scores := map[string]float64{}
	if len(record.Metrics.V31) > 0 {
		scores[record.Metrics.V31[0].CVSS.Version] = record.Metrics.V31[0].CVSS.BaseScore
	} else if len(record.Metrics.V30) > 0 {
		scores[record.Metrics.V30[0].CVSS.Version] = record.Metrics.V30[0].CVSS.BaseScore
	}
	ttl := p.CacheTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	return Enrichment{CVE: record.ID, Description: description, CVSS: scores, References: references, FetchedAt: now, ExpiresAt: now.Add(ttl)}, nil
}

type CISAKEVProvider struct {
	Client     *http.Client
	CatalogURL string
	CacheTTL   time.Duration
	mu         sync.RWMutex
	cache      map[string]KnownExploited
	loadedAt   time.Time
}
type kevCatalog struct {
	Vulnerabilities []struct {
		CVE            string `json:"cveID"`
		DateAdded      string `json:"dateAdded"`
		RequiredAction string `json:"requiredAction"`
		DueDate        string `json:"dueDate"`
	} `json:"vulnerabilities"`
}

func (p *CISAKEVProvider) Lookup(ctx context.Context, cve string) (KnownExploited, error) {
	ttl := p.CacheTTL
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	p.mu.RLock()
	cached, fresh := p.cache[strings.ToUpper(cve)], time.Since(p.loadedAt) < ttl
	p.mu.RUnlock()
	if fresh {
		return cached, nil
	}
	if err := p.refresh(ctx); err != nil {
		return KnownExploited{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cache[strings.ToUpper(cve)], nil
}
func (p *CISAKEVProvider) refresh(ctx context.Context) error {
	catalogURL := p.CatalogURL
	if catalogURL == "" {
		catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
	if err != nil {
		return err
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA KEV returned status %d", response.StatusCode)
	}
	var payload kevCatalog
	if err = json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&payload); err != nil {
		return err
	}
	cache := make(map[string]KnownExploited, len(payload.Vulnerabilities))
	for _, item := range payload.Vulnerabilities {
		dateAdded := parseDate(item.DateAdded)
		dueDate := parseDate(item.DueDate)
		cache[strings.ToUpper(item.CVE)] = KnownExploited{CVE: item.CVE, KnownExploited: true, DateAdded: dateAdded, RequiredAction: item.RequiredAction, DueDate: dueDate}
	}
	p.mu.Lock()
	p.cache = cache
	p.loadedAt = time.Now()
	p.mu.Unlock()
	return nil
}
func parseDate(value string) *time.Time {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return nil
	}
	return &parsed
}
