package reports

type Type string

const (
	NetworkHealth    Type = "NETWORK_HEALTH"
	AssetSecurity    Type = "ASSET_SECURITY"
	Vulnerability    Type = "VULNERABILITY"
	PublicExposure   Type = "PUBLIC_EXPOSURE"
	PCAPAnalysis     Type = "PCAP_ANALYSIS"
	ExecutiveSummary Type = "EXECUTIVE_SUMMARY"
)

type Renderer interface {
	RenderHTML(Type, map[string]any) ([]byte, error)
	RenderPDF(Type, map[string]any) ([]byte, error)
}
