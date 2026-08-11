package traffic

import "time"

type ProtocolStatistic struct {
	Protocol string `json:"protocol"`
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
}
type ConnectionObservation struct {
	Source          string    `json:"source"`
	Destination     string    `json:"destination"`
	SourcePort      int       `json:"sourcePort"`
	DestinationPort int       `json:"destinationPort"`
	Protocol        string    `json:"protocol"`
	StartedAt       time.Time `json:"startedAt"`
	DurationMs      int64     `json:"durationMs"`
	Bytes           int64     `json:"bytes"`
}
type TrafficSummary struct {
	Connections int64               `json:"connections"`
	Bytes       int64               `json:"bytes"`
	Protocols   []ProtocolStatistic `json:"protocols"`
	From        time.Time           `json:"from"`
	Until       time.Time           `json:"until"`
}
