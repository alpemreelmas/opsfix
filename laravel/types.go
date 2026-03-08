package laravel

type HealthStatus struct {
	HTTPStatus   int    `json:"http_status"`
	HTTPBody     string `json:"http_body,omitempty"`
	StorageOK    bool   `json:"storage_writable"`
	CacheOK      bool   `json:"cache_ok"`
	QueueOK      bool   `json:"queue_ok"`
	AppEnv       string `json:"app_env"`
	AppDebug     bool   `json:"app_debug"`
	LaravelVersion string `json:"laravel_version,omitempty"`
}

type ArtisanResult struct {
	Command  string `json:"command"`
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
}
