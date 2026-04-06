package legacy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"netch_go/internal/model"
	appruntime "netch_go/internal/runtime"
)

type Importer struct {
	paths appruntime.Paths
}

func NewImporter(paths appruntime.Paths) *Importer {
	return &Importer{paths: paths}
}

func (i *Importer) Discover() model.LegacyDiscovery {
	settingsCandidates := []string{
		filepath.Join(filepath.Dir(i.paths.RootDir), "Netch", "bin", "x64", "Debug", "data", "settings.json"),
		filepath.Join(filepath.Dir(i.paths.RootDir), "release", "data", "settings.json"),
		filepath.Join(i.paths.DataDir, "legacy_settings.json"),
	}

	settingsPath := ""
	for _, candidate := range settingsCandidates {
		if fileExists(candidate) {
			settingsPath = candidate
			break
		}
	}

	rulesCandidates := []string{
		filepath.Join(i.paths.RuntimeRulesDir, "legacy_mode"),
		filepath.Join(filepath.Dir(i.paths.RootDir), "Storage", "mode"),
	}

	rulesPath := ""
	for _, candidate := range rulesCandidates {
		if dirExists(candidate) {
			rulesPath = candidate
			break
		}
	}

	modeFiles := 0
	if rulesPath != "" {
		_ = filepath.WalkDir(rulesPath, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			if strings.EqualFold(filepath.Ext(path), ".json") {
				modeFiles++
			}
			return nil
		})
	}

	return model.LegacyDiscovery{SettingsPath: settingsPath, RulesPath: rulesPath, ModeFiles: modeFiles}
}

func (i *Importer) Import(cfg *model.AppConfig) (model.ImportReport, error) {
	discovery := i.Discover()
	report := model.ImportReport{Warnings: []string{}}

	if discovery.SettingsPath != "" {
		servers, redirector, dnsCfg, err := loadLegacySettings(discovery.SettingsPath)
		if err != nil {
			report.Warnings = append(report.Warnings, "旧版 settings.json 读取失败: "+err.Error())
		} else {
			existingServers := make(map[string]struct{}, len(cfg.Servers))
			for _, server := range cfg.Servers {
				existingServers[server.Host+":"+server.Name] = struct{}{}
			}
			for _, server := range servers {
				key := server.Host + ":" + server.Name
				if _, exists := existingServers[key]; exists {
					continue
				}
				cfg.Servers = append(cfg.Servers, server)
				existingServers[key] = struct{}{}
				report.ImportedServers++
			}
			cfg.Proxy = redirector
			cfg.DNS.DomesticUpstream = dnsCfg.DomesticUpstream
			cfg.DNS.ProxyUpstream = dnsCfg.ProxyUpstream
		}
	}

	if discovery.RulesPath != "" {
		ruleSets, err := i.loadRuleSets(discovery.RulesPath)
		if err != nil {
			report.Warnings = append(report.Warnings, "旧版规则读取失败: "+err.Error())
		} else {
			existing := make(map[string]struct{}, len(cfg.CustomRuleSets))
			for _, ruleSet := range cfg.CustomRuleSets {
				existing[ruleSet.Name] = struct{}{}
			}
			for _, ruleSet := range ruleSets {
				if _, exists := existing[ruleSet.Name]; exists {
					continue
				}
				cfg.CustomRuleSets = append(cfg.CustomRuleSets, ruleSet)
				existing[ruleSet.Name] = struct{}{}
				report.ImportedRuleSets++
			}
		}
	}

	cfg.Normalize()
	return report, nil
}

type legacySettings struct {
	Server     []legacyServer `json:"Server"`
	Redirector struct {
		FilterTCP     bool   `json:"FilterTCP"`
		FilterUDP     bool   `json:"FilterUDP"`
		FilterDNS     bool   `json:"FilterDNS"`
		FilterParent  bool   `json:"FilterParent"`
		HandleOnlyDNS bool   `json:"HandleOnlyDNS"`
		DNSProxy      bool   `json:"DNSProxy"`
		DNSHost       string `json:"DNSHost"`
		ICMPDelay     int    `json:"ICMPDelay"`
		FilterICMP    bool   `json:"FilterICMP"`
	} `json:"Redirector"`
	AioDNS struct {
		ChinaDNS string `json:"ChinaDNS"`
		OtherDNS string `json:"OtherDNS"`
	} `json:"AioDNS"`
}

type legacyServer struct {
	Type           string `json:"Type"`
	Group          string `json:"Group"`
	Hostname       string `json:"Hostname"`
	Port           int    `json:"Port"`
	Remark         string `json:"Remark"`
	Username       string `json:"Username"`
	Password       string `json:"Password"`
	Version        string `json:"Version"`
	RemoteHostname string `json:"RemoteHostname"`
}

func loadLegacySettings(path string) ([]model.SocksServer, model.ProxyOptions, model.DNSSettings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, model.ProxyOptions{}, model.DNSSettings{}, err
	}

	payload := legacySettings{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, model.ProxyOptions{}, model.DNSSettings{}, err
	}

	servers := make([]model.SocksServer, 0, len(payload.Server))
	for _, server := range payload.Server {
		if !strings.EqualFold(server.Type, "SOCKS") {
			continue
		}
		item := model.SocksServer{
			ID:         model.NewID("srv"),
			Name:       strings.TrimSpace(server.Remark),
			Group:      strings.TrimSpace(server.Group),
			Host:       strings.TrimSpace(server.Hostname),
			Port:       server.Port,
			Username:   strings.TrimSpace(server.Username),
			Password:   strings.TrimSpace(server.Password),
			Version:    strings.TrimSpace(server.Version),
			RemoteHost: strings.TrimSpace(server.RemoteHostname),
		}
		item.Normalize()
		servers = append(servers, item)
	}

	proxy := model.DefaultConfig().Proxy
	proxy.FilterTCP = payload.Redirector.FilterTCP
	proxy.FilterUDP = payload.Redirector.FilterUDP
	proxy.FilterDNS = payload.Redirector.FilterDNS
	proxy.FilterParent = payload.Redirector.FilterParent
	proxy.HandleOnlyDNS = payload.Redirector.HandleOnlyDNS
	proxy.DNSProxy = payload.Redirector.DNSProxy
	proxy.RemoteDNS = payload.Redirector.DNSHost
	proxy.ICMPDelay = payload.Redirector.ICMPDelay
	proxy.FilterICMP = payload.Redirector.FilterICMP

	dnsCfg := model.DefaultConfig().DNS
	if payload.AioDNS.ChinaDNS != "" {
		dnsCfg.DomesticUpstream = payload.AioDNS.ChinaDNS
	}
	if payload.AioDNS.OtherDNS != "" {
		dnsCfg.ProxyUpstream = payload.AioDNS.OtherDNS
	}
	return servers, proxy, dnsCfg, nil
}

func (i *Importer) loadRuleSets(root string) ([]model.RuleSet, error) {
	ruleSets := []model.RuleSet{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		ruleSet, readErr := readLegacyJSONRule(path)
		if readErr == nil {
			ruleSets = append(ruleSets, ruleSet)
		}
		return nil
	})
	return ruleSets, err
}

func readLegacyJSONRule(path string) (model.RuleSet, error) {
	type legacyJSONRule struct {
		Type        any      `json:"type"`
		Remark      any      `json:"remark"`
		Description string   `json:"description"`
		Handle      []string `json:"handle"`
		Bypass      []string `json:"bypass"`
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return model.RuleSet{}, err
	}

	payload := legacyJSONRule{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return model.RuleSet{}, err
	}

	if !isProcessModeType(payload.Type) {
		return model.RuleSet{}, errors.New("not a process mode json")
	}

	name := pickRuleName(payload.Remark, strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))

	description := strings.TrimSpace(payload.Description)
	if description == "" {
		description = "JSON 规则导入"
	}

	ruleSet := model.RuleSet{
		ID:          model.NewID("legacy"),
		Name:        name,
		Description: description,
		Source:      "legacy",
		SourcePath:  path,
		Include:     payload.Handle,
		Exclude:     payload.Bypass,
		ReadOnly:    false,
	}
	ruleSet.Normalize()
	return ruleSet, nil
}

func pickRuleName(value any, fallback string) string {
	switch typed := value.(type) {
	case map[string]any:
		keys := []string{"zh-CN", "zh", "en", "default"}
		for _, key := range keys {
			if text, ok := typed[key].(string); ok {
				text = strings.TrimSpace(text)
				if text != "" {
					return text
				}
			}
		}
		for _, raw := range typed {
			if text, ok := raw.(string); ok {
				text = strings.TrimSpace(text)
				if text != "" {
					return text
				}
			}
		}
	case map[string]string:
		keys := []string{"zh-CN", "zh", "en", "default"}
		for _, key := range keys {
			text := strings.TrimSpace(typed[key])
			if text != "" {
				return text
			}
		}
		for _, text := range typed {
			text = strings.TrimSpace(text)
			if text != "" {
				return text
			}
		}
	case string:
		text := strings.TrimSpace(typed)
		if text != "" {
			return text
		}
	}
	return strings.TrimSpace(fallback)
}

func isProcessModeType(value any) bool {
	switch typed := value.(type) {
	case float64:
		return int(typed) == 0
	case string:
		return strings.EqualFold(typed, "ProcessMode") || strings.EqualFold(typed, "0")
	default:
		return false
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
