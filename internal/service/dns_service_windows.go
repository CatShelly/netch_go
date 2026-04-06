//go:build windows

package service

import (
    "fmt"
    "path/filepath"
    "sync"
    "syscall"
    "unsafe"

    "netch_go/internal/model"
    appruntime "netch_go/internal/runtime"
    "netch_go/internal/windows"
)

const (
    aiodnsReset = iota
    aiodnsList
    aiodnsListen
    aiodnsChinaDNS
    aiodnsOtherDNS
)

type DNSService struct {
    mu        sync.Mutex
    running   bool
    dll       *aioDNSDLL
    snapshots []windows.DNSSnapshot
    logf      func(string, string)
}

func NewDNSService(logf func(string, string)) *DNSService {
    return &DNSService{logf: logf}
}

func (s *DNSService) Start(settings model.DNSSettings, locator *appruntime.AssetLocator, adapters []model.NetworkAdapter) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    if s.running {
        return fmt.Errorf("dns service is already running")
    }

    binaryPath, ok := locator.Resolve("aiodns.bin")
    if !ok {
        return fmt.Errorf("missing aiodns.bin")
    }

    ruleFile, ok := locator.Resolve("aiodns.conf")
    if settings.RuleFile != "" {
        ruleFile = settings.RuleFile
        ok = true
    }
    if !ok {
        return fmt.Errorf("missing aiodns.conf")
    }

    dll, err := newAioDNSDLL(binaryPath)
    if err != nil {
        return err
    }

    if _, err := dll.Dial(aiodnsReset, ""); err != nil {
        return err
    }
    if _, err := dll.Dial(aiodnsList, filepath.Clean(ruleFile)); err != nil {
        return err
    }
    if _, err := dll.Dial(aiodnsListen, settings.Listen); err != nil {
        return err
    }
    if _, err := dll.Dial(aiodnsChinaDNS, settings.DomesticUpstream); err != nil {
        return err
    }
    if _, err := dll.Dial(aiodnsOtherDNS, settings.ProxyUpstream); err != nil {
        return err
    }

    ok, err = dll.Init()
    if err != nil {
        return err
    }
    if !ok {
        return fmt.Errorf("aiodns_init returned false")
    }

    if settings.ApplySystemDNS {
        aliases := windows.SelectManagedAdapters(adapters, settings.ManagedAdapters)
        snapshots, err := windows.CaptureDNSSnapshots(aliases)
        if err != nil {
            _ = dll.Free()
            return err
        }
        for _, alias := range aliases {
            if err := windows.ApplyLoopbackDNS(alias, "127.0.0.1"); err != nil {
                _ = dll.Free()
                return err
            }
        }
        s.snapshots = snapshots
    }

    s.dll = dll
    s.running = true
    s.logf("info", "本地 DNS 服务已启动")
    return nil
}

func (s *DNSService) Stop(restore bool) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    if !s.running {
        return nil
    }

    var stopErr error
    if s.dll != nil {
        stopErr = s.dll.Free()
    }

    if restore {
        for _, snapshot := range s.snapshots {
            if err := windows.RestoreDNS(snapshot); err != nil && stopErr == nil {
                stopErr = err
            }
        }
    }

    s.snapshots = nil
    s.dll = nil
    s.running = false
    s.logf("info", "本地 DNS 服务已停止")
    return stopErr
}

func (s *DNSService) Running() bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.running
}

type aioDNSDLL struct {
    dll  *syscall.LazyDLL
    dial *syscall.LazyProc
    init *syscall.LazyProc
    free *syscall.LazyProc
}

func newAioDNSDLL(path string) (*aioDNSDLL, error) {
    dll := syscall.NewLazyDLL(path)
    if err := dll.Load(); err != nil {
        return nil, err
    }
    return &aioDNSDLL{
        dll:  dll,
        dial: dll.NewProc("aiodns_dial"),
        init: dll.NewProc("aiodns_init"),
        free: dll.NewProc("aiodns_free"),
    }, nil
}

func (d *aioDNSDLL) Dial(name int, value string) (bool, error) {
    ptr, err := syscall.BytePtrFromString(value)
    if err != nil {
        return false, err
    }
    result, _, callErr := d.dial.Call(uintptr(name), uintptr(unsafe.Pointer(ptr)))
    if result == 0 && callErr != syscall.Errno(0) {
        return false, callErr
    }
    return result != 0, nil
}

func (d *aioDNSDLL) Init() (bool, error) {
    result, _, callErr := d.init.Call()
    if result == 0 && callErr != syscall.Errno(0) {
        return false, callErr
    }
    return result != 0, nil
}

func (d *aioDNSDLL) Free() error {
    _, _, callErr := d.free.Call()
    if callErr != syscall.Errno(0) {
        return callErr
    }
    return nil
}
