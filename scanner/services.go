package scanner

import (
	"fmt"
	"strings"

	sshpkg "github.com/alperen/opsfix/ssh"
)

func ListServices(client sshpkg.Client) ([]ServiceInfo, error) {
	res, err := client.Exec("systemctl list-units --type=service --no-pager --no-legend --plain 2>/dev/null")
	if err != nil {
		return nil, fmt.Errorf("list_services: %w", err)
	}

	var services []ServiceInfo
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		services = append(services, ServiceInfo{
			Name:        fields[0],
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
			Description: strings.Join(fields[4:], " "),
		})
	}
	return services, nil
}

func ServiceStatus(client sshpkg.Client, name string) (ServiceInfo, error) {
	// Sanitize service name to prevent injection
	if strings.ContainsAny(name, ";|&`$(){}") {
		return ServiceInfo{}, fmt.Errorf("service_status: invalid service name %q", name)
	}

	res, err := client.Exec(fmt.Sprintf("systemctl show %s --no-pager --property=Id,LoadState,ActiveState,SubState,Description 2>/dev/null", name))
	if err != nil {
		return ServiceInfo{}, fmt.Errorf("service_status %q: %w", name, err)
	}

	info := ServiceInfo{Name: name}
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "LoadState":
			info.LoadState = kv[1]
		case "ActiveState":
			info.ActiveState = kv[1]
		case "SubState":
			info.SubState = kv[1]
		case "Description":
			info.Description = kv[1]
		}
	}
	return info, nil
}
