//go:build windows

package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"netch_go/internal/model"
	appruntime "netch_go/internal/runtime"
)

const (
	redirectorFilterLoopback = iota
	redirectorFilterIntranet
	redirectorFilterParent
	redirectorFilterICMP
	redirectorFilterTCP
	redirectorFilterUDP
	redirectorFilterDNS
	redirectorICMPDelay
	redirectorDNSOnly
	redirectorDNSProxy
	redirectorDNSHost
	redirectorDNSPort
	redirectorTargetHost
	redirectorTargetPort
	redirectorTargetUser
	redirectorTargetPass
	redirectorClearName
	redirectorAddName
	redirectorBypassName
	redirectorDNSDomainOnly
	redirectorClearDomainRule
	redirectorAddDomainRule
)

type ProcessProxyService struct {
	mu      sync.Mutex
	running bool
	dll     *redirectorDLL
	paths   appruntime.Paths
	logf    func(string, string)
}

func NewProcessProxyService(paths appruntime.Paths, logf func(string, string)) *ProcessProxyService {
	return &ProcessProxyService{paths: paths, logf: logf}
}

func (s *ProcessProxyService) Start(server model.SocksServer, ruleSet model.RuleSet, options model.ProxyOptions, locator *appruntime.AssetLocator) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("process proxy is already running")
	}
	if !isElevated() {
		return fmt.Errorf("需要管理员权限启动强制代理，请以管理员身份运行程序")
	}

	redirectorPath, ok := locator.Resolve("Redirector.bin")
	if !ok {
		return fmt.Errorf("missing Redirector.bin")
	}
	nfapiPath, ok := locator.Resolve("nfapi.dll")
	if !ok {
		return fmt.Errorf("missing nfapi.dll")
	}
	driverPath, ok := locator.Resolve("nfdriver.sys")
	if !ok {
		return fmt.Errorf("missing nfdriver.sys")
	}
	logArtifactMeta(s.logf, "Redirector.bin", redirectorPath)
	logArtifactMeta(s.logf, "nfapi.dll", nfapiPath)
	logArtifactMeta(s.logf, "nfdriver.sys", driverPath)
	if err := ensureDLLSearchPath(filepath.Dir(redirectorPath)); err != nil {
		return fmt.Errorf("prepare dll search path failed: %w", err)
	}
	if err := preloadDLL(nfapiPath); err != nil {
		return fmt.Errorf("preload nfapi.dll failed (%s): %w", nfapiPath, err)
	}

	dll, err := newRedirectorDLL(redirectorPath)
	if err != nil {
		return fmt.Errorf("load Redirector.bin failed (%s): %w (通常是依赖 DLL 未找到)", redirectorPath, err)
	}
	s.logf("info", "正在注册/检查 netfilter2 驱动")
	if err := ensureDriver(dll, driverPath); err != nil {
		return fmt.Errorf("prepare netfilter driver failed: %w", err)
	}
	s.logf("info", "netfilter2 驱动检查完成，正在下发 Redirector 参数")
	s.logf("info", fmt.Sprintf("Redirector 参数: TCP=%t UDP=%t DNS=%t DNSONLY=%t DNSProxy=%t RemoteDNS=%s", options.FilterTCP, options.FilterUDP, options.FilterDNS, options.HandleOnlyDNS, options.DNSProxy, options.RemoteDNS))
	if err := dialRedirectorOptions(dll, server, ruleSet, options, s.paths.RootDir); err != nil {
		return fmt.Errorf("apply redirector options failed: %w", err)
	}

	ok, err = dll.Init()
	if err != nil {
		return fmt.Errorf("redirector init call failed: %w", err)
	}
	if !ok {
		return errors.New("redirector init returned false（可能已有另一个实例占用驱动，请关闭旧的 netch_go / wails dev 进程后重试）")
	}

	s.dll = dll
	s.running = true
	s.logf("info", "进程强制代理已启动")
	return nil
}

func (s *ProcessProxyService) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	var stopErr error
	if s.dll != nil {
		stopErr = s.dll.Free()
	}
	s.dll = nil
	s.running = false
	s.logf("info", "进程强制代理已停止")
	return stopErr
}

func (s *ProcessProxyService) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func dialRedirectorOptions(dll *redirectorDLL, server model.SocksServer, ruleSet model.RuleSet, options model.ProxyOptions, rootDir string) error {
	if _, err := dll.DialBool(redirectorFilterLoopback, options.FilterLoopback); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorFilterIntranet, options.FilterIntranet); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorFilterParent, options.FilterParent); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorFilterICMP, options.FilterICMP); err != nil {
		return err
	}
	if options.FilterICMP {
		if _, err := dll.DialString(redirectorICMPDelay, fmt.Sprintf("%d", options.ICMPDelay)); err != nil {
			return err
		}
	}
	if _, err := dll.DialBool(redirectorFilterTCP, options.FilterTCP); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorFilterUDP, options.FilterUDP); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorFilterDNS, options.FilterDNS); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorDNSOnly, options.HandleOnlyDNS); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorDNSProxy, options.DNSProxy); err != nil {
		return err
	}
	if _, err := dll.DialBool(redirectorDNSDomainOnly, options.DNSDomainOnly); err != nil {
		return err
	}

	if options.FilterDNS {
		host, port, err := net.SplitHostPort(options.RemoteDNS)
		if err != nil {
			return fmt.Errorf("invalid remote dns %q: %w", options.RemoteDNS, err)
		}
		if _, err := dll.DialString(redirectorDNSHost, host); err != nil {
			return err
		}
		if _, err := dll.DialString(redirectorDNSPort, port); err != nil {
			return err
		}
	}

	resolvedHost, err := resolveIPv4(server.Host)
	if err != nil {
		return err
	}
	if _, err := dll.DialString(redirectorTargetHost, resolvedHost); err != nil {
		return err
	}
	if _, err := dll.DialString(redirectorTargetPort, fmt.Sprintf("%d", server.Port)); err != nil {
		return err
	}
	if _, err := dll.DialString(redirectorTargetUser, server.Username); err != nil {
		return err
	}
	if _, err := dll.DialString(redirectorTargetPass, server.Password); err != nil {
		return err
	}

	if _, err := dll.DialString(redirectorClearName, ""); err != nil {
		return err
	}

	invalid := []string{}
	for _, value := range ruleSet.Exclude {
		ok, err := dll.DialString(redirectorBypassName, value)
		if err != nil {
			return err
		}
		if !ok {
			invalid = append(invalid, value)
		}
	}
	for _, value := range ruleSet.Include {
		ok, err := dll.DialString(redirectorAddName, value)
		if err != nil {
			return err
		}
		if !ok {
			invalid = append(invalid, value)
		}
	}
	if _, err := dll.DialString(redirectorClearDomainRule, ""); err != nil {
		return err
	}
	for _, value := range ruleSet.DomainRules {
		ok, err := dll.DialString(redirectorAddDomainRule, value)
		if err != nil {
			return err
		}
		if !ok {
			invalid = append(invalid, "domain:"+value)
		}
	}

	if _, err := dll.DialString(redirectorBypassName, "^"+regexp.QuoteMeta(rootDir)); err != nil {
		return err
	}
	if len(invalid) > 0 {
		return fmt.Errorf("invalid redirector rules: %s", strings.Join(invalid, ", "))
	}
	return nil
}

func resolveIPv4(host string) (string, error) {
	addresses, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if ipv4 := address.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no ipv4 address found for %s", host)
}

func ensureDriver(dll *redirectorDLL, sourceDriver string) error {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		return fmt.Errorf("WINDIR is empty")
	}

	systemDriver := filepath.Join(windir, "System32", "drivers", "netfilter2.sys")
	if _, err := os.Stat(systemDriver); errors.Is(err, os.ErrNotExist) {
		if err := copyDriver(sourceDriver, systemDriver); err != nil {
			return fmt.Errorf("copy netfilter2.sys failed: %w", err)
		}
	}

	ok, err := dll.Register("netfilter2")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("aio_register returned false (可能是权限不足或驱动服务状态异常)")
	}
	return nil
}

func isElevated() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

func logArtifactMeta(logf func(string, string), name, path string) {
	info, err := os.Stat(path)
	if err != nil {
		logf("warn", fmt.Sprintf("读取运行时组件信息失败: %s (%s): %v", name, path, err))
		return
	}
	logf("info", fmt.Sprintf("运行时组件 %s: %s (size=%d, mtime=%s)", name, path, info.Size(), info.ModTime().Format(time.RFC3339)))
}

func ensureDLLSearchPath(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("empty dll directory")
	}
	currentPath := os.Getenv("PATH")
	entries := strings.Split(currentPath, ";")
	for _, entry := range entries {
		if strings.EqualFold(strings.TrimSpace(entry), dir) {
			return nil
		}
	}
	if currentPath == "" {
		return os.Setenv("PATH", dir)
	}
	return os.Setenv("PATH", dir+";"+currentPath)
}

func preloadDLL(path string) error {
	dll := syscall.NewLazyDLL(path)
	return dll.Load()
}

type redirectorDLL struct {
	dll      *syscall.LazyDLL
	register *syscall.LazyProc
	dial     *syscall.LazyProc
	init     *syscall.LazyProc
	free     *syscall.LazyProc
}

func newRedirectorDLL(path string) (*redirectorDLL, error) {
	dll := syscall.NewLazyDLL(path)
	if err := dll.Load(); err != nil {
		return nil, err
	}
	return &redirectorDLL{
		dll:      dll,
		register: dll.NewProc("aio_register"),
		dial:     dll.NewProc("aio_dial"),
		init:     dll.NewProc("aio_init"),
		free:     dll.NewProc("aio_free"),
	}, nil
}

func (d *redirectorDLL) Register(name string) (bool, error) {
	ptr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	result, _, callErr := d.register.Call(uintptr(unsafe.Pointer(ptr)))
	if result == 0 && callErr != syscall.Errno(0) {
		return false, callErr
	}
	return result != 0, nil
}

func (d *redirectorDLL) DialBool(name int, value bool) (bool, error) {
	if value {
		return d.DialString(name, "true")
	}
	return d.DialString(name, "false")
}

func (d *redirectorDLL) DialString(name int, value string) (bool, error) {
	ptr, err := syscall.UTF16PtrFromString(value)
	if err != nil {
		return false, err
	}
	result, _, callErr := d.dial.Call(uintptr(name), uintptr(unsafe.Pointer(ptr)))
	if result == 0 && callErr != syscall.Errno(0) {
		return false, callErr
	}
	return result != 0, nil
}

func (d *redirectorDLL) Init() (bool, error) {
	result, _, callErr := d.init.Call()
	if result == 0 && callErr != syscall.Errno(0) {
		return false, callErr
	}
	return result != 0, nil
}

func (d *redirectorDLL) Free() error {
	_, _, callErr := d.free.Call()
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return nil
}

func copyDriver(source, target string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}
