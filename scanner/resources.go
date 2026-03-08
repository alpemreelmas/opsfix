package scanner

import (
	"fmt"
	"strconv"
	"strings"

	sshpkg "github.com/alperen/opsfix/ssh"
)

func DiskUsage(client sshpkg.Client) ([]DiskEntry, error) {
	res, err := client.Exec("df -h --output=source,size,used,avail,pcent,target 2>/dev/null | tail -n +2")
	if err != nil {
		return nil, fmt.Errorf("disk_usage: %w", err)
	}

	var entries []DiskEntry
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		entries = append(entries, DiskEntry{
			Filesystem: fields[0],
			Size:       fields[1],
			Used:       fields[2],
			Available:  fields[3],
			UsePercent: fields[4],
			MountPoint: fields[5],
		})
	}
	return entries, nil
}

func MemoryUsage(client sshpkg.Client) (MemoryInfo, error) {
	res, err := client.Exec("cat /proc/meminfo 2>/dev/null")
	if err != nil {
		return MemoryInfo{}, fmt.Errorf("memory_usage: %w", err)
	}

	vals := make(map[string]int64)
	for _, line := range strings.Split(res.Stdout, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		vals[key] = val
	}

	total := vals["MemTotal"]
	free := vals["MemFree"]
	available := vals["MemAvailable"]
	cached := vals["Cached"]

	return MemoryInfo{
		TotalKB:     total,
		FreeKB:      free,
		AvailableKB: available,
		UsedKB:      total - free,
		CachedKB:    cached,
	}, nil
}

func CPUUsage(client sshpkg.Client) (CPUInfo, error) {
	res, err := client.Exec("cat /proc/loadavg && nproc 2>/dev/null")
	if err != nil {
		return CPUInfo{}, fmt.Errorf("cpu_usage: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	if len(lines) < 2 {
		return CPUInfo{}, fmt.Errorf("cpu_usage: unexpected output")
	}

	loadFields := strings.Fields(lines[0])
	if len(loadFields) < 3 {
		return CPUInfo{}, fmt.Errorf("cpu_usage: parse load avg")
	}

	parseFloat := func(s string) float64 {
		v, _ := strconv.ParseFloat(s, 64)
		return v
	}

	numCPU, _ := strconv.Atoi(strings.TrimSpace(lines[1]))

	return CPUInfo{
		LoadAvg1:  parseFloat(loadFields[0]),
		LoadAvg5:  parseFloat(loadFields[1]),
		LoadAvg15: parseFloat(loadFields[2]),
		NumCPU:    numCPU,
	}, nil
}

func QueueStatus(client sshpkg.Client) ([]QueueWorker, error) {
	res, err := client.Exec("supervisorctl status 2>/dev/null")
	if err != nil {
		return nil, fmt.Errorf("queue_status: %w", err)
	}

	var workers []QueueWorker
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		w := QueueWorker{
			Name:   fields[0],
			Status: fields[1],
		}

		// Parse PID and uptime if running: "pid 1234, uptime 0:01:23"
		if len(fields) > 3 && fields[2] == "pid" {
			pidStr := strings.TrimSuffix(fields[3], ",")
			pid, _ := strconv.Atoi(pidStr)
			w.PID = pid
			if len(fields) > 5 {
				w.Uptime = fields[5]
			}
		}

		workers = append(workers, w)
	}
	return workers, nil
}
