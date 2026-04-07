package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"netch_go/internal/config"
	"netch_go/internal/legacy"
	"netch_go/internal/model"
	appruntime "netch_go/internal/runtime"
	"netch_go/internal/service"
	"netch_go/internal/windows"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const ruleScanMaxCount = 50

type App struct {
	ctx      context.Context
	paths    appruntime.Paths
	store    *config.Store
	importer *legacy.Importer
	assets   *appruntime.AssetLocator
	session  *service.SessionManager
	dnsWatch *service.DNSCaptureMonitor

	mu     sync.Mutex
	config model.AppConfig
	logs   []model.LogEntry

	tray       trayController
	forceExit  bool
	trayHidden bool

	exitWatchdogOnce sync.Once
}

const (
	closeActionMinimize = "minimize"
	closeActionExit     = "exit"
)

type trayController interface {
	Start() error
	Stop()
	IsReady() bool
}

func NewApp() (*App, error) {
	paths, err := appruntime.DiscoverPaths()
	if err != nil {
		return nil, err
	}

	store := config.NewStore(paths)
	cfg, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(cfg.CustomRuleSets) > 0 {
		cfg.CustomRuleSets = []model.RuleSet{}
		if err := store.Save(cfg); err != nil {
			return nil, err
		}
	}

	app := &App{
		paths:    paths,
		store:    store,
		importer: legacy.NewImporter(paths),
		assets:   appruntime.NewAssetLocator(paths),
		config:   cfg,
		logs: []model.LogEntry{{
			Time:    model.Timestamp(),
			Level:   "info",
			Message: "Netch Go 后端已初始化",
		}},
	}
	app.session = service.NewSessionManager(paths, app.assets, app.pushLog)
	app.dnsWatch = service.NewDNSCaptureMonitor(app.pushLog, app.emitDNSWatchDomain)
	return app, nil
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
	a.startTray()
	a.pushLog("info", "Wails UI 已连接")
	if !windows.IsElevated() {
		a.pushLog("warn", "当前进程不是管理员权限，强制代理启动会失败。请用管理员终端运行 wails dev 或运行构建后的 exe。")
	}
}

func (a *App) DomReady(ctx context.Context) {
	_ = ctx
}

func (a *App) BeforeClose(ctx context.Context) bool {
	if a.consumeForceExit() {
		a.prepareExit()
		return false
	}

	action := a.getCloseAction()
	if action == closeActionMinimize {
		return a.closeToTray()
	}
	a.prepareExit()
	return false
}

func (a *App) closeToTray() bool {
	if !a.trayReady() {
		a.startTray()
	}
	if !a.trayReady() {
		a.pushLog("warn", "托盘初始化失败，无法最小化到托盘，已按直接退出处理")
		a.prepareExit()
		return false
	}
	a.pushLog("info", "窗口已最小化到托盘")
	if a.ctx != nil {
		wailsruntime.WindowHide(a.ctx)
		a.setTrayHidden(true)
		return true
	}
	// If window context is unavailable, do not block close forever.
	a.prepareExit()
	return false
}

func (a *App) Shutdown(ctx context.Context) {
	a.stopSessionForExit("程序退出，正在清理强制代理会话")
	a.stopDNSWatchForExit()
	a.stopTray()
}

func (a *App) GetBootstrap() (model.BootstrapState, error) {
	return a.bootstrapState()
}

func (a *App) PrepareRuntimeAssets() (model.BootstrapState, error) {
	actions, err := a.assets.PrepareRuntime()
	if err != nil {
		return model.BootstrapState{}, err
	}
	if len(actions) == 0 {
		a.pushLog("warn", "没有找到可复制的旧版运行时文件")
	} else {
		a.pushLog("info", "运行时资源已准备: "+strings.Join(actions, ", "))
	}
	return a.bootstrapState()
}

func (a *App) ImportLegacyData() (model.BootstrapState, error) {
	a.mu.Lock()
	report, err := a.importer.Import(&a.config)
	if err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	importedRules := append([]model.RuleSet(nil), a.config.CustomRuleSets...)
	a.config.CustomRuleSets = []model.RuleSet{}
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()

	for _, rule := range importedRules {
		if _, err := a.upsertRuleSetFile(rule); err != nil {
			report.Warnings = append(report.Warnings, "规则写入 runtime/rules 失败: "+rule.Name+" / "+err.Error())
		}
	}

	a.pushLog("info", fmt.Sprintf("已导入旧版数据: %d 个服务器, %d 个规则集", report.ImportedServers, report.ImportedRuleSets))
	for _, warning := range report.Warnings {
		a.pushLog("warn", warning)
	}
	return a.bootstrapState()
}

func (a *App) UpsertServer(server model.SocksServer) (model.BootstrapState, error) {
	a.mu.Lock()
	server.Normalize()
	replaced := false
	for index, item := range a.config.Servers {
		if item.ID == server.ID {
			a.config.Servers[index] = server
			replaced = true
			break
		}
	}
	if !replaced {
		a.config.Servers = append(a.config.Servers, server)
	}
	if a.config.Selection.ServerID == "" {
		a.config.Selection.ServerID = server.ID
	}
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	a.pushLog("info", "服务器配置已保存: "+server.Name)
	return a.bootstrapState()
}

func (a *App) DeleteServer(id string) (model.BootstrapState, error) {
	a.mu.Lock()
	kept := make([]model.SocksServer, 0, len(a.config.Servers))
	for _, server := range a.config.Servers {
		if server.ID != id {
			kept = append(kept, server)
		}
	}
	a.config.Servers = kept
	if a.config.Selection.ServerID == id {
		a.config.Selection.ServerID = ""
	}
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	a.pushLog("info", "服务器配置已删除")
	return a.bootstrapState()
}

func (a *App) UpsertRuleSet(ruleSet model.RuleSet) (model.BootstrapState, error) {
	saved, err := a.upsertRuleSetFile(ruleSet)
	if err != nil {
		return model.BootstrapState{}, err
	}

	a.mu.Lock()
	a.config.Selection.RuleSetID = saved.ID
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	a.pushLog("info", "规则集已保存: "+saved.Name)
	return a.bootstrapState()
}

func (a *App) DeleteRuleSet(id string) (model.BootstrapState, error) {
	deleted, err := a.deleteRuleSetFileByID(id)
	if err != nil {
		return model.BootstrapState{}, err
	}

	a.mu.Lock()
	if a.config.Selection.RuleSetID == id {
		a.config.Selection.RuleSetID = ""
	}
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	if deleted {
		a.pushLog("info", "规则集已删除")
	}
	return a.bootstrapState()
}

func (a *App) SaveProxyOptions(options model.ProxyOptions) (model.BootstrapState, error) {
	a.mu.Lock()
	options.Normalize()
	a.config.Proxy = options
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	a.pushLog("info", fmt.Sprintf("全局代理模板已更新: TCP=%t UDP=%t DNS=%t DNSONLY=%t DNSProxy=%t DNSDomainOnly=%t", options.FilterTCP, options.FilterUDP, options.FilterDNS, options.HandleOnlyDNS, options.DNSProxy, options.DNSDomainOnly))
	if options.FilterDNS {
		if options.DNSDomainOnly {
			a.pushLog("info", "DNS 重定向范围：仅 svchost 且命中“域名规则”的请求。")
		} else if options.HandleOnlyDNS {
			a.pushLog("info", "DNS 重定向范围：仅命中规则进程。")
		} else {
			a.pushLog("info", "DNS 重定向范围：命中规则进程 + DNS Client(svchost)。")
		}
	}
	if !options.FilterTCP && !options.FilterUDP && !options.FilterDNS {
		a.pushLog("warn", "当前 TCP / UDP / DNS 全部关闭，启动后不会接管任何流量。")
	}
	return a.bootstrapState()
}

func (a *App) SaveDNSSettings(settings model.DNSSettings) (model.BootstrapState, error) {
	a.mu.Lock()
	a.config.DNS = settings
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	a.pushLog("info", fmt.Sprintf("DNS 配置已更新: Enabled=%t ApplySystemDNS=%t RestoreOnStop=%t", settings.Enabled, settings.ApplySystemDNS, settings.RestoreOnStop))
	return a.bootstrapState()
}

func (a *App) SaveSelection(selection model.SelectionState) (model.BootstrapState, error) {
	a.mu.Lock()
	a.config.Selection = selection
	if err := a.store.Save(a.config); err != nil {
		a.mu.Unlock()
		return model.BootstrapState{}, err
	}
	a.mu.Unlock()
	return a.bootstrapState()
}

func (a *App) SaveCloseAction(action string) (model.BootstrapState, error) {
	finalAction, err := a.setCloseAction(action)
	if err != nil {
		return model.BootstrapState{}, err
	}
	if finalAction == closeActionMinimize {
		a.pushLog("info", "关闭行为已更新: 最小化到托盘")
	} else {
		a.pushLog("info", "关闭行为已更新: 直接退出")
	}
	return a.bootstrapState()
}

func (a *App) StartSession() (model.BootstrapState, error) {
	a.mu.Lock()
	cfg := a.config
	a.mu.Unlock()

	if a.session.Status().Running {
		a.pushLog("info", "检测到会话已运行，正在重新启动强制代理")
		a.session.Stop(cfg.DNS.RestoreOnStop)
	}

	ruleSets, adapters, err := a.stateParts()
	if err != nil {
		return model.BootstrapState{}, err
	}

	type startResult struct {
		err error
	}
	resultCh := make(chan startResult, 1)
	go func() {
		_, err := a.session.Start(cfg, ruleSets, adapters)
		resultCh <- startResult{err: err}
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			a.pushLog("error", result.err.Error())
			return a.bootstrapState()
		}
	case <-time.After(12 * time.Second):
		a.pushLog("error", "启动超时：可能驱动服务状态异常或存在旧进程占用，请先停止旧实例后重试")
		return a.bootstrapState()
	}
	return a.bootstrapState()
}

func (a *App) StopSession() (model.BootstrapState, error) {
	a.session.Stop(a.config.DNS.RestoreOnStop)
	return a.bootstrapState()
}

func (a *App) GetDNSCaptureState() model.DNSCaptureState {
	return a.dnsWatch.Status()
}

func (a *App) SetDNSCaptureEnabled(enabled bool) (model.DNSCaptureState, error) {
	sessionRunning := a.session.Status().Running

	ruleSet := model.RuleSet{}
	if enabled {
		selected, err := a.selectedRuleSetForDNSWatch()
		if err != nil {
			return a.dnsWatch.Status(), err
		}
		ruleSet = selected
	}

	state, err := a.dnsWatch.SetEnabled(enabled, sessionRunning, ruleSet)
	if err != nil {
		return state, err
	}
	return state, nil
}

func (a *App) selectedRuleSetForDNSWatch() (model.RuleSet, error) {
	a.mu.Lock()
	selectedID := strings.TrimSpace(a.config.Selection.RuleSetID)
	a.mu.Unlock()

	if selectedID == "" {
		return model.RuleSet{}, fmt.Errorf("请先选择一个规则集，再开启 DNS Client ETW 抓取")
	}

	ruleSets, _, err := a.stateParts()
	if err != nil {
		return model.RuleSet{}, err
	}
	for _, ruleSet := range ruleSets {
		if ruleSet.ID == selectedID {
			return ruleSet, nil
		}
	}
	return model.RuleSet{}, fmt.Errorf("当前选择的规则集不存在，请重新选择后再开启 DNS Client ETW 抓取")
}

func (a *App) OpenRuntimeDir() error {
	return windows.OpenDirectory(a.paths.RuntimeDir)
}

func (a *App) OpenDataDir() error {
	return windows.OpenDirectory(a.paths.DataDir)
}

func (a *App) ScanRuleIncludeExecutables() ([]string, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("UI context is not ready")
	}

	dir, err := wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择要扫描的目录（递归导入 EXE）",
	})
	if err != nil {
		return nil, err
	}

	dir = strings.TrimSpace(dir)
	if dir == "" {
		return []string{}, nil
	}

	rules, err := scanExecutableRules(dir, ruleScanMaxCount)
	if err != nil {
		return nil, err
	}

	a.pushLog("info", fmt.Sprintf("已扫描目录: %s，导入 %d 条可执行文件规则", dir, len(rules)))
	return rules, nil
}

func (a *App) bootstrapState() (model.BootstrapState, error) {
	ruleSets, adapters, err := a.stateParts()
	if err != nil {
		return model.BootstrapState{}, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	return model.BootstrapState{
		Config:   a.config,
		RuleSets: ruleSets,
		Adapters: adapters,
		Assets:   a.assets.Inspect(),
		Session:  a.session.Status(),
		DNSWatch: a.dnsWatch.Status(),
		Logs:     append([]model.LogEntry(nil), a.logs...),
		Legacy:   model.LegacyDiscovery{},
	}, nil
}

func (a *App) stateParts() ([]model.RuleSet, []model.NetworkAdapter, error) {
	ruleSets, err := a.loadRuleSetsFromRuntime()
	if err != nil {
		return nil, nil, err
	}
	return ruleSets, []model.NetworkAdapter{}, nil
}

func (a *App) pushLog(level, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entry := model.LogEntry{Time: model.Timestamp(), Level: strings.ToLower(level), Message: message}
	a.logs = append(a.logs, entry)
	if len(a.logs) > 200 {
		a.logs = a.logs[len(a.logs)-200:]
	}
	if a.ctx != nil {
		go wailsruntime.EventsEmit(a.ctx, "netch:log", entry)
	}
}

func (a *App) emitDNSWatchDomain(domain string) {
	if strings.TrimSpace(domain) == "" {
		return
	}
	if a.ctx != nil {
		go wailsruntime.EventsEmit(a.ctx, "netch:dns-query", domain)
	}
}

func (a *App) stopSessionForExit(reason string) {
	a.mu.Lock()
	restore := a.config.DNS.RestoreOnStop
	a.mu.Unlock()

	_ = reason
	done := make(chan struct{})
	go func() {
		_ = a.session.Stop(restore)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
	}
}

func (a *App) stopDNSWatchForExit() {
	if a.dnsWatch == nil {
		return
	}
	_, _ = a.dnsWatch.SetEnabled(false, false, model.RuleSet{})
}

func (a *App) prepareExit() {
	a.stopSessionForExit("窗口关闭，正在自动停止强制代理会话")
	a.stopDNSWatchForExit()
	a.armExitWatchdog()
}

func (a *App) startTray() {
	tray := newTrayController(a)
	if tray == nil {
		return
	}
	if err := tray.Start(); err != nil {
		a.pushLog("warn", "托盘初始化失败: "+err.Error())
		return
	}
	a.mu.Lock()
	old := a.tray
	a.tray = tray
	a.mu.Unlock()
	if old != nil && old != tray {
		old.Stop()
	}
}

func (a *App) stopTray() {
	a.mu.Lock()
	tray := a.tray
	a.tray = nil
	a.mu.Unlock()
	if tray != nil {
		tray.Stop()
	}
}

func (a *App) trayReady() bool {
	a.mu.Lock()
	tray := a.tray
	a.mu.Unlock()
	if tray == nil {
		return false
	}
	return tray.IsReady()
}

func (a *App) showWindowFromTray() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowShow(a.ctx)
	a.setTrayHidden(false)
}

func (a *App) hideWindowFromTray() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowHide(a.ctx)
	a.setTrayHidden(true)
}

func (a *App) requestQuitFromTray() {
	a.mu.Lock()
	a.forceExit = true
	ctx := a.ctx
	a.mu.Unlock()
	if ctx != nil {
		wailsruntime.Quit(ctx)
		return
	}
	a.prepareExit()
}

func (a *App) consumeForceExit() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.forceExit {
		return false
	}
	a.forceExit = false
	return true
}

func (a *App) setTrayHidden(hidden bool) {
	a.mu.Lock()
	a.trayHidden = hidden
	a.mu.Unlock()
}

func (a *App) isTrayHidden() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.trayHidden
}

func (a *App) getCloseAction() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return normalizeCloseAction(a.config.UI.CloseAction)
}

func normalizeCloseAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case closeActionMinimize:
		return closeActionMinimize
	case "ask", "":
		return closeActionExit
	default:
		return closeActionExit
	}
}

func (a *App) setCloseAction(action string) (string, error) {
	action = normalizeCloseAction(action)

	a.mu.Lock()
	a.config.UI.CloseAction = action
	cfg := a.config
	a.mu.Unlock()

	if err := a.store.Save(cfg); err != nil {
		return action, err
	}
	return action, nil
}

func (a *App) armExitWatchdog() {
	a.exitWatchdogOnce.Do(func() {
		go func() {
			time.Sleep(3 * time.Second)
			os.Exit(0)
		}()
	})
}

func scanExecutableRules(root string, maxCount int) ([]string, error) {
	seen := make(map[string]struct{})
	rules := make([]string, 0, 16)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}

		name := d.Name()
		if !strings.EqualFold(filepath.Ext(name), ".exe") {
			return nil
		}

		rule := regexp.QuoteMeta(name)
		if _, ok := seen[rule]; ok {
			return nil
		}
		seen[rule] = struct{}{}
		rules = append(rules, rule)

		if maxCount > 0 && len(rules) > maxCount {
			return fmt.Errorf("目录中的可执行文件数量超过上限 %d，请缩小扫描范围后再试", maxCount)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(rules)
	return rules, nil
}
