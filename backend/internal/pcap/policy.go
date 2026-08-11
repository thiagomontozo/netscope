package pcap

import "time"
const DefaultRetention=7*24*time.Hour
type Access struct{CanUpload bool;CanRead bool;CanDownload bool;CanDelete bool}
func CanAccessRaw(a Access)bool{return a.CanRead&&a.CanDownload}
