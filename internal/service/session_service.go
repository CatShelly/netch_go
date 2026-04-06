package service

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"netch_go/internal/model"
	appruntime "netch_go/internal/runtime"
)

type SessionManager struct {
	mu      sync.RWMutex
	opMu    sync.Mutex
	proxy   *ProcessProxyService
	status  model.SessionStatus
	locator *appruntime.AssetLocator
	logf    func(string, string)
}

func NewSessionManager(paths appruntime.Paths, locator *appruntime.AssetLocator, logf func(string, string)) *SessionManager {
	if logf == nil {
		logf = func(string, string) {}
	}
	return &SessionManager{
		proxy:   NewProcessProxyService(paths, logf),
		locator: locator,
		logf:    logf,
		status:  model.SessionStatus{Message: "未启动"},
	}
}

func (s *SessionManager) Start(cfg model.AppConfig, ruleSets []model.RuleSet, adapters []model.NetworkAdapter) (model.SessionStatus, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.RLock()
	running := s.status.Running
	current := s.status
	s.mu.RUnlock()

	_ = adapters

	if running {
		return current, fmt.Errorf("session is already running")
	}

	server, ok := findServer(cfg.Servers, cfg.Selection.ServerID)
	if !ok {
		return current, fmt.Errorf("请选择一个 SOCKS 服务器")
	}
	ruleSet, ok := findRuleSet(ruleSets, cfg.Selection.RuleSetID)
	if !ok {
		return current, fmt.Errorf("请选择一个规则集")
	}

	effectiveProxy := ruleSet.Proxy
	effectiveProxy.Normalize()
	if !anyTrafficEnabled(effectiveProxy) {
		next := model.SessionStatus{
			Message: "当前规则集的进程重定向选项无效",
			Warnings: []string{
				fmt.Sprintf("规则集 %s 的 TCP / UDP / DNS 全部关闭。", ruleSet.Name),
				"请在规则集里至少启用一种拦截：TCP / UDP / DNS。",
			},
		}
		s.mu.Lock()
		s.status = next
		s.mu.Unlock()
		return next, fmt.Errorf("rule set redirector options disable all traffic")
	}
	if effectiveProxy.FilterDNS && effectiveProxy.DNSProxy && isPrivateDNSRemote(effectiveProxy.RemoteDNS) {
		s.logf("warn", fmt.Sprintf("检测到重定向 DNS 目标 %s 是内网/本地地址，自动关闭“DNS 请求走代理”以避免请求到不了目标 DNS", effectiveProxy.RemoteDNS))
		effectiveProxy.DNSProxy = false
	}
	s.logf("info", fmt.Sprintf(
		"启动参数: Redirector[TCP=%t UDP=%t DNS=%t DNSONLY=%t DNSProxy=%t DNSDomainOnly=%t RemoteDNS=%s]",
		effectiveProxy.FilterTCP,
		effectiveProxy.FilterUDP,
		effectiveProxy.FilterDNS,
		effectiveProxy.HandleOnlyDNS,
		effectiveProxy.DNSProxy,
		effectiveProxy.DNSDomainOnly,
		effectiveProxy.RemoteDNS,
	))
	if effectiveProxy.FilterDNS {
		if effectiveProxy.DNSDomainOnly {
			s.logf("info", "进程 DNS 重定向已启用：处理 svchost 且命中“域名规则”的请求。")
		} else if effectiveProxy.HandleOnlyDNS {
			s.logf("info", "进程 DNS 重定向已启用：仅命中规则进程会被重定向。")
		} else {
			s.logf("info", "进程 DNS 重定向已启用：命中规则进程 + DNS Client(svchost) 会被重定向。")
		}
	}

	s.logf("info", fmt.Sprintf("当前选择: 服务器=%s 规则=%s(包含=%d,绕过=%d,域名=%d)", server.Name, ruleSet.Name, len(ruleSet.Include), len(ruleSet.Exclude), len(ruleSet.DomainRules)))

	missing := collectMissingAssets(s.locator.Inspect(), requiredAssets())
	if len(missing) > 0 {
		warnings := []string{
			fmt.Sprintf("当前运行时目录: %s", s.locator.Paths.RuntimeDir),
			fmt.Sprintf("缺少组件: %s", strings.Join(missing, ", ")),
			"请先准备 C++ 运行时资源，确保 Redirector.bin / nfapi.dll / nfdriver.sys 可用。",
		}
		next := model.SessionStatus{
			Message:       "运行时组件不完整",
			MissingAssets: missing,
			Warnings:      warnings,
		}
		s.mu.Lock()
		s.status = next
		s.mu.Unlock()
		return next, fmt.Errorf("missing runtime assets")
	}

	if err := s.proxy.Start(server, ruleSet, effectiveProxy, s.locator); err != nil {
		next := model.SessionStatus{
			Message:      "强制代理启动失败",
			Warnings:     []string{err.Error()},
			DNSRunning:   false,
			ProxyRunning: false,
		}
		s.mu.Lock()
		s.status = next
		s.mu.Unlock()
		return next, err
	}

	next := model.SessionStatus{
		Running:       true,
		DNSRunning:    false,
		ProxyRunning:  true,
		StartedAt:     model.Timestamp(),
		Message:       fmt.Sprintf("已启动: %s / %s", server.Name, ruleSet.Name),
		MissingAssets: []string{},
		Warnings:      []string{},
	}
	s.mu.Lock()
	s.status = next
	s.mu.Unlock()
	return next, nil
}

func (s *SessionManager) Stop(restoreDNS bool) model.SessionStatus {
	s.opMu.Lock()
	defer s.opMu.Unlock()

	_ = restoreDNS
	if err := s.proxy.Stop(); err != nil {
		s.logf("warn", "停止进程强制代理时发生错误: "+err.Error())
	}
	next := model.SessionStatus{Message: "已停止"}
	s.mu.Lock()
	s.status = next
	s.mu.Unlock()
	return next
}

func (s *SessionManager) Status() model.SessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func findServer(servers []model.SocksServer, id string) (model.SocksServer, bool) {
	for _, server := range servers {
		if server.ID == id {
			return server, true
		}
	}
	return model.SocksServer{}, false
}

func findRuleSet(ruleSets []model.RuleSet, id string) (model.RuleSet, bool) {
	for _, ruleSet := range ruleSets {
		if ruleSet.ID == id {
			return ruleSet, true
		}
	}
	return model.RuleSet{}, false
}

func requiredAssets() []string {
	return []string{"Redirector.bin", "nfapi.dll", "nfdriver.sys"}
}

func collectMissingAssets(checks []model.AssetCheck, required []string) []string {
	requiredSet := make(map[string]struct{}, len(required))
	for _, name := range required {
		requiredSet[name] = struct{}{}
	}

	result := []string{}
	for _, check := range checks {
		if _, ok := requiredSet[check.Name]; !ok {
			continue
		}
		if check.Status != "ready" {
			result = append(result, check.Name)
		}
	}
	return result
}

func anyTrafficEnabled(proxy model.ProxyOptions) bool {
	return proxy.FilterTCP || proxy.FilterUDP || proxy.FilterDNS
}

func isPrivateDNSRemote(remote string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
