package model

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

type AppConfig struct {
	Servers        []SocksServer  `json:"servers"`
	CustomRuleSets []RuleSet      `json:"customRuleSets"`
	Selection      SelectionState `json:"selection"`
	Proxy          ProxyOptions   `json:"proxy"`
	DNS            DNSSettings    `json:"dns"`
	UI             UISettings     `json:"ui"`
}

type SocksServer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Group      string `json:"group"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Version    string `json:"version"`
	RemoteHost string `json:"remoteHost"`
	Notes      string `json:"notes"`
	UpdatedAt  string `json:"updatedAt"`
}

type RuleSet struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Source      string       `json:"source"`
	SourcePath  string       `json:"sourcePath"`
	Tag         string       `json:"tag"`
	Include     []string     `json:"include"`
	Exclude     []string     `json:"exclude"`
	DomainRules []string     `json:"domainRules"`
	Proxy       ProxyOptions `json:"proxy"`
	ReadOnly    bool         `json:"readOnly"`
	UpdatedAt   string       `json:"updatedAt"`
}

type SelectionState struct {
	ServerID  string `json:"serverId"`
	RuleSetID string `json:"ruleSetId"`
}

type ProxyOptions struct {
	FilterLoopback bool   `json:"filterLoopback"`
	FilterIntranet bool   `json:"filterIntranet"`
	FilterParent   bool   `json:"filterParent"`
	FilterICMP     bool   `json:"filterICMP"`
	FilterTCP      bool   `json:"filterTCP"`
	FilterUDP      bool   `json:"filterUDP"`
	FilterDNS      bool   `json:"filterDNS"`
	HandleOnlyDNS  bool   `json:"handleOnlyDns"`
	DNSProxy       bool   `json:"dnsProxy"`
	DNSDomainOnly  bool   `json:"dnsDomainOnly"`
	RemoteDNS      string `json:"remoteDns"`
	ICMPDelay      int    `json:"icmpDelay"`
}

type DNSSettings struct {
	Enabled          bool     `json:"enabled"`
	Listen           string   `json:"listen"`
	DomesticUpstream string   `json:"domesticUpstream"`
	ProxyUpstream    string   `json:"proxyUpstream"`
	RuleFile         string   `json:"ruleFile"`
	ApplySystemDNS   bool     `json:"applySystemDns"`
	ManagedAdapters  []string `json:"managedAdapters"`
	RestoreOnStop    bool     `json:"restoreOnStop"`
}

type UISettings struct {
	AutoImportLegacy bool `json:"autoImportLegacy"`
}

type NetworkAdapter struct {
	Alias       string   `json:"alias"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	IPv4        []string `json:"ipv4"`
}

type AssetCheck struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type SessionStatus struct {
	Running       bool     `json:"running"`
	ProxyRunning  bool     `json:"proxyRunning"`
	DNSRunning    bool     `json:"dnsRunning"`
	StartedAt     string   `json:"startedAt"`
	Message       string   `json:"message"`
	MissingAssets []string `json:"missingAssets"`
	Warnings      []string `json:"warnings"`
}

type DNSCaptureState struct {
	Enabled        bool     `json:"enabled"`
	ChannelEnabled bool     `json:"channelEnabled"`
	Capturing      bool     `json:"capturing"`
	Message        string   `json:"message"`
	Domains        []string `json:"domains"`
}

type LogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type LegacyDiscovery struct {
	SettingsPath string `json:"settingsPath"`
	RulesPath    string `json:"rulesPath"`
	ModeFiles    int    `json:"modeFiles"`
}

type ImportReport struct {
	ImportedServers  int      `json:"importedServers"`
	ImportedRuleSets int      `json:"importedRuleSets"`
	Warnings         []string `json:"warnings"`
}

type BootstrapState struct {
	Config   AppConfig        `json:"config"`
	RuleSets []RuleSet        `json:"ruleSets"`
	Adapters []NetworkAdapter `json:"adapters"`
	Assets   []AssetCheck     `json:"assets"`
	Session  SessionStatus    `json:"session"`
	DNSWatch DNSCaptureState  `json:"dnsWatch"`
	Logs     []LogEntry       `json:"logs"`
	Legacy   LegacyDiscovery  `json:"legacy"`
}

func DefaultConfig() AppConfig {
	return AppConfig{
		Servers:        []SocksServer{},
		CustomRuleSets: []RuleSet{},
		Selection:      SelectionState{},
		Proxy: ProxyOptions{
			FilterLoopback: false,
			FilterIntranet: true,
			FilterParent:   false,
			FilterICMP:     false,
			FilterTCP:      true,
			FilterUDP:      true,
			FilterDNS:      true,
			HandleOnlyDNS:  false,
			DNSProxy:       false,
			DNSDomainOnly:  false,
			RemoteDNS:      "1.1.1.1:53",
			ICMPDelay:      10,
		},
		DNS: DNSSettings{
			Enabled:          false,
			Listen:           "127.0.0.1:53",
			DomesticUpstream: "tcp://223.5.5.5:53",
			ProxyUpstream:    "tcp://1.1.1.1:53",
			RuleFile:         "",
			ApplySystemDNS:   false,
			ManagedAdapters:  []string{},
			RestoreOnStop:    true,
		},
		UI: UISettings{AutoImportLegacy: true},
	}
}

func (c *AppConfig) Normalize() {
	defaults := DefaultConfig()
	c.Proxy.Normalize()
	if c.DNS.Listen == "" {
		c.DNS.Listen = defaults.DNS.Listen
	}
	if c.DNS.DomesticUpstream == "" {
		c.DNS.DomesticUpstream = defaults.DNS.DomesticUpstream
	}
	if c.DNS.ProxyUpstream == "" {
		c.DNS.ProxyUpstream = defaults.DNS.ProxyUpstream
	}
	c.DNS.ManagedAdapters = UniqueNonEmpty(c.DNS.ManagedAdapters)
	for i := range c.Servers {
		c.Servers[i].Normalize()
	}
	for i := range c.CustomRuleSets {
		c.CustomRuleSets[i].Normalize()
	}
}

func (s *SocksServer) Normalize() {
	s.ID = strings.TrimSpace(s.ID)
	if s.ID == "" {
		s.ID = NewID("srv")
	}
	s.Name = strings.TrimSpace(s.Name)
	s.Group = strings.TrimSpace(s.Group)
	s.Host = strings.TrimSpace(s.Host)
	s.Username = strings.TrimSpace(s.Username)
	s.Password = strings.TrimSpace(s.Password)
	s.Version = strings.TrimSpace(s.Version)
	if s.Version == "" {
		s.Version = "5"
	}
	s.RemoteHost = strings.TrimSpace(s.RemoteHost)
	s.Notes = strings.TrimSpace(s.Notes)
	if s.Port <= 0 {
		s.Port = 1080
	}
	if s.Name == "" {
		s.Name = s.Host
	}
	s.UpdatedAt = Timestamp()
}

func (r *RuleSet) Normalize() {
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		r.ID = NewID("rule")
	}
	r.Name = strings.TrimSpace(r.Name)
	r.Description = strings.TrimSpace(r.Description)
	r.Source = strings.TrimSpace(r.Source)
	if r.Source == "" {
		r.Source = "custom"
	}
	r.SourcePath = strings.TrimSpace(r.SourcePath)
	r.Tag = strings.TrimSpace(r.Tag)
	r.Include = UniqueNonEmpty(r.Include)
	r.Exclude = UniqueNonEmpty(r.Exclude)
	r.DomainRules = UniqueNonEmpty(r.DomainRules)
	r.Proxy.Normalize()
	r.UpdatedAt = Timestamp()
}

func (p *ProxyOptions) Normalize() {
	defaults := DefaultConfig().Proxy
	if strings.TrimSpace(p.RemoteDNS) == "" {
		p.RemoteDNS = defaults.RemoteDNS
	}
	if p.ICMPDelay < 0 {
		p.ICMPDelay = defaults.ICMPDelay
	}
}

func Timestamp() string {
	return time.Now().Format(time.RFC3339)
}

func NewID(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return prefix + "_" + strings.ReplaceAll(Timestamp(), ":", "-")
	}
	return prefix + "_" + hex.EncodeToString(buf)
}

func UniqueNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
