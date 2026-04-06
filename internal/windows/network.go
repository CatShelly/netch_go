//go:build windows

package windows

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"

	xwindows "golang.org/x/sys/windows"
	"netch_go/internal/model"
)

type DNSSnapshot struct {
	InterfaceAlias  string   `json:"InterfaceAlias"`
	ServerAddresses []string `json:"ServerAddresses"`
}

func ListAdapters() ([]model.NetworkAdapter, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := make([]model.NetworkAdapter, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		status := "down"
		if iface.Flags&net.FlagUp != 0 {
			status = "up"
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		ipv4 := []string{}
		for _, addr := range addrs {
			var ip net.IP
			switch typed := addr.(type) {
			case *net.IPNet:
				ip = typed.IP
			case *net.IPAddr:
				ip = typed.IP
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			ipv4 = append(ipv4, ip.String())
		}

		result = append(result, model.NetworkAdapter{
			Alias:       iface.Name,
			Description: iface.Name,
			Status:      status,
			IPv4:        model.UniqueNonEmpty(ipv4),
		})
	}

	return result, nil
}

func CaptureDNSSnapshots(aliases []string) ([]DNSSnapshot, error) {
	if len(aliases) == 0 {
		return nil, nil
	}

	script := fmt.Sprintf(
		"$aliases = @(%s); Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $aliases -contains $_.InterfaceAlias } | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Depth 4 -Compress",
		quoteArray(aliases),
	)

	output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("capture dns snapshot failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return decodeJSONSlice[DNSSnapshot](output)
}

func ApplyLoopbackDNS(alias, address string) error {
	return runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf(`name=%q`, alias), "static", address, "primary")
}

func RestoreDNS(snapshot DNSSnapshot) error {
	if len(snapshot.ServerAddresses) == 0 {
		return runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf(`name=%q`, snapshot.InterfaceAlias), "source=dhcp")
	}

	if err := runNetsh("interface", "ipv4", "set", "dnsservers", fmt.Sprintf(`name=%q`, snapshot.InterfaceAlias), "static", snapshot.ServerAddresses[0], "primary"); err != nil {
		return err
	}

	for index, address := range snapshot.ServerAddresses[1:] {
		if err := runNetsh("interface", "ipv4", "add", "dnsservers", fmt.Sprintf(`name=%q`, snapshot.InterfaceAlias), fmt.Sprintf("address=%s", address), fmt.Sprintf("index=%d", index+2)); err != nil {
			return err
		}
	}
	return nil
}

func OpenDirectory(path string) error {
	return exec.Command("explorer.exe", path).Start()
}

func IsElevated() bool {
	token := xwindows.GetCurrentProcessToken()
	return token.IsElevated()
}

func SelectManagedAdapters(all []model.NetworkAdapter, preferred []string) []string {
	if len(preferred) > 0 {
		return model.UniqueNonEmpty(preferred)
	}

	aliases := []string{}
	for _, adapter := range all {
		if adapter.Status != "up" || len(adapter.IPv4) == 0 {
			continue
		}
		aliases = append(aliases, adapter.Alias)
	}
	return model.UniqueNonEmpty(aliases)
}

func decodeJSONSlice[T any](data []byte) ([]T, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	if strings.HasPrefix(trimmed, "{") {
		var item T
		if err := json.Unmarshal([]byte(trimmed), &item); err != nil {
			return nil, err
		}
		return []T{item}, nil
	}

	var items []T
	if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
		return nil, err
	}
	return items, nil
}

func quoteArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ReplaceAll(value, "'", "''")
		quoted = append(quoted, "'"+value+"'")
	}
	return strings.Join(quoted, ",")
}

func runNetsh(args ...string) error {
	output, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
