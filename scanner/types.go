package scanner

type ServiceInfo struct {
	Name        string `json:"name"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	Description string `json:"description"`
}

type ResourceMetrics struct {
	DiskUsage   []DiskEntry   `json:"disk_usage"`
	MemoryUsage MemoryInfo    `json:"memory_usage"`
	CPUUsage    CPUInfo       `json:"cpu_usage"`
}

type DiskEntry struct {
	Filesystem string `json:"filesystem"`
	Size       string `json:"size"`
	Used       string `json:"used"`
	Available  string `json:"available"`
	UsePercent string `json:"use_percent"`
	MountPoint string `json:"mount_point"`
}

type MemoryInfo struct {
	TotalKB     int64 `json:"total_kb"`
	AvailableKB int64 `json:"available_kb"`
	UsedKB      int64 `json:"used_kb"`
	FreeKB      int64 `json:"free_kb"`
	CachedKB    int64 `json:"cached_kb"`
}

type CPUInfo struct {
	LoadAvg1  float64 `json:"load_avg_1m"`
	LoadAvg5  float64 `json:"load_avg_5m"`
	LoadAvg15 float64 `json:"load_avg_15m"`
	NumCPU    int     `json:"num_cpu"`
}

type QueueWorker struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	PID     int    `json:"pid"`
	Uptime  string `json:"uptime"`
}

type ScanResult struct {
	Server   string          `json:"server"`
	Services []ServiceInfo   `json:"services"`
	Resources ResourceMetrics `json:"resources"`
	Queues   []QueueWorker   `json:"queues"`
}
