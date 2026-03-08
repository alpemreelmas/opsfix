package scanner

import (
	"encoding/json"
	"fmt"

	sshpkg "github.com/alperen/opsfix/ssh"
)

type Scanner struct {
	pool *sshpkg.Pool
}

func New(pool *sshpkg.Pool) *Scanner {
	return &Scanner{pool: pool}
}

func (s *Scanner) ScanServer(serverName string) (string, error) {
	client, err := s.pool.Get(serverName)
	if err != nil {
		return "", fmt.Errorf("scan_server: %w", err)
	}

	result := ScanResult{Server: serverName}

	if svcs, err := ListServices(client); err == nil {
		result.Services = svcs
	}

	disk, _ := DiskUsage(client)
	mem, _ := MemoryUsage(client)
	cpu, _ := CPUUsage(client)
	result.Resources = ResourceMetrics{
		DiskUsage:   disk,
		MemoryUsage: mem,
		CPUUsage:    cpu,
	}

	queues, _ := QueueStatus(client)
	result.Queues = queues

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("scan_server: marshal: %w", err)
	}

	return string(out), nil
}
