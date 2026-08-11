package modules

import (
	"encoding/json"
	"github.com/thiagomontozo/netscope/backend/internal/domain"
	"time"
)

func BuiltinDefinitions() []Adapter {
	all := []domain.ScopeEnvironment{domain.EnvironmentInternal, domain.EnvironmentPublic}
	passive := []domain.ScopeEnvironment{domain.EnvironmentInternal, domain.EnvironmentPublic}
	definition := func(id, name, category string, risk domain.RiskClass, capability string, timeout time.Duration) domain.ModuleDefinition {
		return domain.ModuleDefinition{ID: id, Name: name, Version: "0.1.0", Category: category, RiskClass: risk, ProtocolVersion: domain.AgentProtocolVersion, SupportedEnvironments: all, SupportedPlatforms: []string{"linux", "windows", "darwin"}, RequiredCapabilities: []string{capability}, DefaultTimeout: timeout, ParameterSchemaVersion: "1.0", ResultSchemaVersion: "1.0", InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false}`), ResultSchema: json.RawMessage(`{"type":"object"}`), Enabled: true}
	}
	adapters := []Adapter{
		{Definition: definition("network.ping", "Ping", "diagnostics", domain.RiskSafeActive, "ping", 30*time.Second), Validator: NewStrictValidator(map[string]func(any) bool{"samples": NumberRange(1, 10), "timeoutMs": NumberRange(100, 10000)})},
		{Definition: definition("network.route", "Route", "diagnostics", domain.RiskSafeActive, "route", 60*time.Second), Validator: NewStrictValidator(map[string]func(any) bool{"maxHops": NumberRange(1, 32), "timeoutMs": NumberRange(100, 10000)})},
		{Definition: definition("network.dns", "DNS", "diagnostics", domain.RiskSafeActive, "dns", 15*time.Second), Validator: NewStrictValidator(map[string]func(any) bool{"recordType": StringEnum("A", "AAAA", "CNAME", "MX", "TXT", "NS")})},
		{Definition: definition("network.tcp", "TCP reachability", "diagnostics", domain.RiskSafeActive, "tcp", 15*time.Second), Validator: NewStrictValidator(map[string]func(any) bool{"port": NumberRange(1, 65535), "timeoutMs": NumberRange(100, 10000)})},
		{Definition: definition("network.http", "HTTP health", "diagnostics", domain.RiskSafeActive, "http", 30*time.Second), Validator: NewStrictValidator(map[string]func(any) bool{"method": StringEnum("HEAD", "GET"), "redirectLimit": NumberRange(0, 5), "expectedStatus": NumberRange(100, 599), "maxResponseBytes": NumberRange(0, 1048576)})},
		{Definition: definition("network.tls", "TLS inspection", "diagnostics", domain.RiskSafeActive, "tls", 20*time.Second), Validator: NewStrictValidator(map[string]func(any) bool{"port": NumberRange(1, 65535), "expiryWarningDays": NumberRange(1, 365)})},
		{Definition: definition("nmap.discovery", "Restricted discovery", "inventory", domain.RiskControlledActive, "nmap", 5*time.Minute), Validator: NewStrictValidator(map[string]func(any) bool{"profile": StringEnum("DISCOVERY"), "maxHosts": NumberRange(1, 256)})},
		{Definition: definition("nmap.services", "Authorized service inventory", "inventory", domain.RiskControlledActive, "nmap", 10*time.Minute), Validator: NewStrictValidator(map[string]func(any) bool{"profile": StringEnum("COMMON_SERVICES", "AUTHORIZED_SERVICE_INVENTORY"), "maxHosts": NumberRange(1, 64)})},
		{Definition: definition("performance.iperf3", "Controlled performance test", "performance", domain.RiskControlledActive, "iperf3", 2*time.Minute), Validator: NewStrictValidator(map[string]func(any) bool{"destinationEndpointId": NonEmptyString, "durationSeconds": NumberRange(1, 30)})},
	}
	for _, item := range []struct{ id, name, category, capability string }{{"traffic.tshark", "TShark PCAP metadata", "traffic", "tshark"}, {"traffic.zeek", "Zeek PCAP analysis", "traffic", "zeek"}, {"security.suricata", "Suricata PCAP analysis", "security", "suricata"}} {
		d := definition(item.id, item.name, item.category, domain.RiskPassive, item.capability, 30*time.Minute)
		d.SupportedEnvironments = passive
		adapters = append(adapters, Adapter{Definition: d, Validator: NewStrictValidator(map[string]func(any) bool{"artifactId": func(v any) bool { s, ok := v.(string); return ok && len(s) > 0 }, "preset": StringEnum("METADATA", "PROTOCOL_SUMMARY", "EVE_IMPORT")})})
	}
	adapters = append(adapters, Adapter{Definition: definition("vulnerability.greenbone", "Greenbone authorized assessment", "vulnerability", domain.RiskControlledActive, "greenbone", 4*time.Hour), Validator: NewStrictValidator(map[string]func(any) bool{"profile": StringEnum("SAFE_AUTHORIZED_SCAN")})})
	return adapters
}
