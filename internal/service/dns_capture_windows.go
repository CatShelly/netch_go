//go:build windows

package service

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"netch_go/internal/model"
)

const (
	dnsClientOperationalLog = "Microsoft-Windows-DNS-Client/Operational"
	dnsClientEventQuery     = "*"
	dnsCaptureProcessTick   = 2 * time.Second
	dnsCaptureMaxDomains    = 200
	dnsCapturePIDHoldTTL    = 90 * time.Second
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXML          = 1
	evtSubscribeActionError    = 0
	evtSubscribeActionDeliver  = 1
)

var (
	wevtapiDLL      = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = wevtapiDLL.NewProc("EvtSubscribe")
	procEvtRender    = wevtapiDLL.NewProc("EvtRender")
	procEvtClose     = wevtapiDLL.NewProc("EvtClose")
	evtSubscribeCB   = syscall.NewCallback(evtSubscribeCallback)

	dnsSubscribeSeq   uint64
	dnsSubscribeSinks sync.Map // map[uintptr]*dnsSubscribeSink
)

type dnsSubscribeSink struct {
	rows chan dnsEventRow
	errs chan error
}

type dnsEventRow struct {
	RecordID  uint64 `json:"recordId"`
	EventID   uint32 `json:"eventId"`
	QueryName string `json:"queryName"`
	ClientPID uint32 `json:"clientPid"`
}

type dnsRuleMatcher struct {
	include []*regexp.Regexp
	exclude []*regexp.Regexp
}

func newDNSRuleMatcher(ruleSet model.RuleSet) (dnsRuleMatcher, error) {
	compileList := func(values []string, field string) ([]*regexp.Regexp, error) {
		result := make([]*regexp.Regexp, 0, len(values))
		for _, raw := range values {
			pattern := strings.TrimSpace(raw)
			if pattern == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				return nil, fmt.Errorf("规则集%s规则无效: %q: %w", field, pattern, err)
			}
			result = append(result, re)
		}
		return result, nil
	}

	include, err := compileList(ruleSet.Include, "包含")
	if err != nil {
		return dnsRuleMatcher{}, err
	}
	exclude, err := compileList(ruleSet.Exclude, "绕过")
	if err != nil {
		return dnsRuleMatcher{}, err
	}
	if len(include) == 0 {
		return dnsRuleMatcher{}, fmt.Errorf("当前规则集没有“包含规则”，无法按命中进程过滤 DNS 域名")
	}

	return dnsRuleMatcher{
		include: include,
		exclude: exclude,
	}, nil
}

func (m dnsRuleMatcher) MatchProcess(processTexts []string) bool {
	normalized := make([]string, 0, len(processTexts))
	for _, text := range processTexts {
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		normalized = append(normalized, text)
	}
	if len(normalized) == 0 {
		return false
	}
	for _, re := range m.exclude {
		for _, text := range normalized {
			if re.MatchString(text) {
				return false
			}
		}
	}
	for _, re := range m.include {
		for _, text := range normalized {
			if re.MatchString(text) {
				return true
			}
		}
	}
	return false
}

type DNSCaptureMonitor struct {
	mu sync.Mutex

	logf      func(string, string)
	onDomain  func(string)
	enabled   bool
	capturing bool

	channelEnabled bool
	message        string
	domains        []string
	domainSet      map[string]struct{}
	cancel         context.CancelFunc

	matcher      dnsRuleMatcher
	pidMatchHint map[uint32]pidMatchResult
	activePIDs   map[uint32]pidSeen
}

type pidMatchResult struct {
	matched bool
	texts   []string
}

type pidSeen struct {
	name   string
	seenAt time.Time
}

func NewDNSCaptureMonitor(logf func(string, string), onDomain func(string)) *DNSCaptureMonitor {
	if logf == nil {
		logf = func(string, string) {}
	}
	if onDomain == nil {
		onDomain = func(string) {}
	}
	return &DNSCaptureMonitor{
		logf:           logf,
		onDomain:       onDomain,
		channelEnabled: true,
		message:        "未开启 DNS Client ETW 抓取",
		domains:        []string{},
		domainSet:      map[string]struct{}{},
		pidMatchHint:   map[uint32]pidMatchResult{},
		activePIDs:     map[uint32]pidSeen{},
	}
}

func (m *DNSCaptureMonitor) Status() model.DNSCaptureState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *DNSCaptureMonitor) SetEnabled(enabled bool, sessionRunning bool, ruleSet model.RuleSet) (model.DNSCaptureState, error) {
	if !enabled {
		m.mu.Lock()
		m.stopLocked("DNS Client ETW 抓取已关闭")
		status := m.statusLocked()
		m.mu.Unlock()
		m.logf("info", status.Message)
		return status, nil
	}

	m.mu.Lock()
	if m.capturing {
		status := m.statusLocked()
		m.mu.Unlock()
		return status, nil
	}
	m.mu.Unlock()

	matcher, err := newDNSRuleMatcher(ruleSet)
	if err != nil {
		return m.failEnable(err.Error())
	}

	channelEnabled, err := isDNSClientChannelEnabled()
	if err != nil {
		return m.failEnable(fmt.Sprintf("检查 DNS Client ETW 通道状态失败: %v", err))
	}
	if !channelEnabled {
		m.mu.Lock()
		m.channelEnabled = false
		m.mu.Unlock()
		return m.failEnable("DNS Client ETW 日志未开启，请先启用“Microsoft-Windows-DNS-Client/Operational”")
	}
	m.mu.Lock()
	m.channelEnabled = true
	m.mu.Unlock()

	if sessionRunning {
		return m.failEnable("当前强制代理服务已启动，请先停止服务，再开启 DNS Client ETW 抓取")
	}
	if err := flushDNSCache(); err != nil {
		return m.failEnable(fmt.Sprintf("执行 ipconfig /flushdns 失败: %v", err))
	}

	ctx, cancel := context.WithCancel(context.Background())

	m.mu.Lock()
	if m.capturing {
		cancel()
		status := m.statusLocked()
		m.mu.Unlock()
		return status, nil
	}
	m.enabled = true
	m.capturing = true
	m.channelEnabled = true
	m.message = "DNS Client ETW 抓取已开启（原生订阅），正在按规则匹配进程过滤域名"
	m.cancel = cancel
	m.matcher = matcher
	m.domains = []string{}
	m.domainSet = map[string]struct{}{}
	m.pidMatchHint = map[uint32]pidMatchResult{}
	m.activePIDs = map[uint32]pidSeen{}
	status := m.statusLocked()
	m.mu.Unlock()

	m.logf("info", fmt.Sprintf("DNS Client ETW 抓取已开启：规则集=%s，已执行 flushdns，使用原生订阅模式", ruleSet.Name))

	go m.processScanOnce()
	go m.subscribeLoop(ctx)
	go m.processScanLoop(ctx)

	return status, nil
}

func (m *DNSCaptureMonitor) failEnable(message string) (model.DNSCaptureState, error) {
	m.mu.Lock()
	m.enabled = false
	m.capturing = false
	m.message = message
	m.pidMatchHint = map[uint32]pidMatchResult{}
	m.activePIDs = map[uint32]pidSeen{}
	status := m.statusLocked()
	m.mu.Unlock()
	m.logf("warn", message)
	return status, errors.New(message)
}

func (m *DNSCaptureMonitor) stopLocked(message string) {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.enabled = false
	m.capturing = false
	m.pidMatchHint = map[uint32]pidMatchResult{}
	m.activePIDs = map[uint32]pidSeen{}
	if strings.TrimSpace(message) != "" {
		m.message = message
	}
}

func (m *DNSCaptureMonitor) statusLocked() model.DNSCaptureState {
	return model.DNSCaptureState{
		Enabled:        m.enabled,
		ChannelEnabled: m.channelEnabled,
		Capturing:      m.capturing,
		Message:        m.message,
		Domains:        append([]string(nil), m.domains...),
	}
}

func (m *DNSCaptureMonitor) processScanLoop(ctx context.Context) {
	ticker := time.NewTicker(dnsCaptureProcessTick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.processScanOnce()
		}
	}
}

func (m *DNSCaptureMonitor) processScanOnce() {
	m.mu.Lock()
	matcher := m.matcher
	m.mu.Unlock()

	matchedNow := scanMatchedProcessHints(matcher)

	now := time.Now()
	m.mu.Lock()
	for pid, hint := range matchedNow {
		m.activePIDs[pid] = pidSeen{name: hint, seenAt: now}
	}
	for pid, info := range m.activePIDs {
		if now.Sub(info.seenAt) > dnsCapturePIDHoldTTL {
			delete(m.activePIDs, pid)
		}
	}
	m.mu.Unlock()
}

func (m *DNSCaptureMonitor) subscribeLoop(ctx context.Context) {
	err := subscribeDNSClientEvents(ctx, func(row dnsEventRow) {
		m.handleEventRow(row)
	})
	if err == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	default:
		m.logf("warn", fmt.Sprintf("DNS Client ETW 原生订阅异常: %v", err))
	}
}

func (m *DNSCaptureMonitor) handleEventRow(row dnsEventRow) {
	pid := row.ClientPID
	if pid == 0 {
		return
	}

	m.mu.Lock()
	matched := false
	processTexts := []string{}
	if hint, ok := m.activePIDs[pid]; ok {
		matched = true
		processTexts = []string{hint.name}
	} else {
		matched, processTexts = m.isMatchedClientPIDLocked(pid)
		if matched && len(processTexts) > 0 {
			m.activePIDs[pid] = pidSeen{name: processTexts[0], seenAt: time.Now()}
		}
	}
	m.mu.Unlock()

	if !matched {
		return
	}
	domain := normalizeDomain(row.QueryName)
	if domain == "" {
		return
	}
	m.ingestDomains([]string{domain})
}

func (m *DNSCaptureMonitor) ingestDomains(domains []string) {
	added := []string{}

	m.mu.Lock()
	for _, raw := range domains {
		domain := normalizeDomain(raw)
		if domain == "" {
			continue
		}
		if _, exists := m.domainSet[domain]; exists {
			continue
		}
		m.domainSet[domain] = struct{}{}
		m.domains = append(m.domains, domain)
		added = append(added, domain)
		if len(m.domains) > dnsCaptureMaxDomains {
			removed := m.domains[0]
			m.domains = m.domains[1:]
			delete(m.domainSet, removed)
		}
	}
	m.mu.Unlock()

	for _, domain := range added {
		m.onDomain(domain)
	}
}

func (m *DNSCaptureMonitor) isMatchedClientPIDLocked(pid uint32) (bool, []string) {
	if cached, ok := m.pidMatchHint[pid]; ok {
		return cached.matched, append([]string(nil), cached.texts...)
	}
	processTexts := queryProcessMatchTexts(pid)
	if len(processTexts) == 0 {
		return false, nil
	}
	matched := m.matcher.MatchProcess(processTexts)
	m.pidMatchHint[pid] = pidMatchResult{matched: matched, texts: append([]string(nil), processTexts...)}
	return matched, processTexts
}

func queryProcessMatchTexts(pid uint32) []string {
	texts := []string{}
	seen := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		texts = append(texts, value)
	}

	if processPath, err := queryProcessImagePath(pid); err == nil {
		add(processPath)
		add(filepath.Base(processPath))
	}

	if exeName, err := queryProcessImageNameBySnapshot(pid); err == nil {
		add(exeName)
	}

	return texts
}

func scanMatchedProcessHints(matcher dnsRuleMatcher) map[uint32]string {
	result := map[uint32]string{}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return result
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return result
	}

	for {
		pid := entry.ProcessID
		if pid != 0 {
			exeName := strings.TrimSpace(syscall.UTF16ToString(entry.ExeFile[:]))
			texts := []string{}
			if exeName != "" {
				texts = append(texts, exeName)
			}

			if matcher.MatchProcess(texts) {
				result[pid] = exeName
			} else if processPath, err := queryProcessImagePath(pid); err == nil {
				more := []string{processPath, filepath.Base(processPath)}
				if matcher.MatchProcess(more) {
					result[pid] = processPath
				}
			}
		}

		err := windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return result
}

func queryProcessImagePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	for size := uint32(260); size <= 32768; size *= 2 {
		buffer := make([]uint16, size)
		actual := uint32(len(buffer))
		err = windows.QueryFullProcessImageName(handle, 0, &buffer[0], &actual)
		if err == nil {
			return syscall.UTF16ToString(buffer[:actual]), nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", err
		}
	}
	return "", fmt.Errorf("query process image path failed for pid %d", pid)
}

func queryProcessImageNameBySnapshot(pid uint32) (string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return "", err
	}

	for {
		if entry.ProcessID == pid {
			name := syscall.UTF16ToString(entry.ExeFile[:])
			name = strings.TrimSpace(name)
			if name == "" {
				return "", fmt.Errorf("empty process name for pid %d", pid)
			}
			return name, nil
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return "", fmt.Errorf("pid %d not found", pid)
	}
	return "", err
}

func normalizeDomain(raw string) string {
	name := strings.TrimSpace(strings.ToLower(raw))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "_") {
		return ""
	}
	if len(name) > 253 {
		return ""
	}
	return name
}

func isDNSClientChannelEnabled() (bool, error) {
	out, err := runPowerShell(
		"$log = Get-WinEvent -ListLog '" + dnsClientOperationalLog + "' -ErrorAction Stop;" +
			"if ($log.IsEnabled) { 'true' } else { 'false' }",
	)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(out), "true"), nil
}

func flushDNSCache() error {
	cmd := exec.Command("ipconfig", "/flushdns")
	hideCommandWindow(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func subscribeDNSClientEvents(ctx context.Context, onRow func(dnsEventRow)) error {
	if onRow == nil {
		return fmt.Errorf("dns event sink is nil")
	}

	channel, err := syscall.UTF16PtrFromString(dnsClientOperationalLog)
	if err != nil {
		return fmt.Errorf("invalid event log name: %w", err)
	}
	query, err := syscall.UTF16PtrFromString(dnsClientEventQuery)
	if err != nil {
		return fmt.Errorf("invalid event query: %w", err)
	}

	sink := &dnsSubscribeSink{
		rows: make(chan dnsEventRow, 256),
		errs: make(chan error, 8),
	}
	ctxID := registerDNSSubscribeSink(sink)
	defer unregisterDNSSubscribeSink(ctxID)

	subscription, _, callErr := procEvtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(channel)),
		uintptr(unsafe.Pointer(query)),
		0,
		ctxID,
		evtSubscribeCB,
		uintptr(evtSubscribeToFutureEvents),
	)
	if subscription == 0 {
		return fmt.Errorf("EvtSubscribe failed: %w", unwrapCallErr(callErr))
	}
	defer evtCloseHandle(subscription)

	for {
		select {
		case <-ctx.Done():
			return nil
		case row := <-sink.rows:
			onRow(row)
		case subErr := <-sink.errs:
			return subErr
		}
	}
}

func evtRenderXML(eventHandle uintptr) (string, error) {
	var bufferUsed uint32
	var propertyCount uint32

	r1, _, callErr := procEvtRender.Call(
		0,
		eventHandle,
		uintptr(evtRenderEventXML),
		0,
		0,
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if r1 == 0 {
		errno := unwrapCallErr(callErr)
		if !errors.Is(errno, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", fmt.Errorf("EvtRender(size) failed: %w", errno)
		}
	}
	if bufferUsed == 0 {
		return "", nil
	}

	buffer := make([]uint16, (bufferUsed+1)/2)
	r1, _, callErr = procEvtRender.Call(
		0,
		eventHandle,
		uintptr(evtRenderEventXML),
		uintptr(bufferUsed),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("EvtRender(xml) failed: %w", unwrapCallErr(callErr))
	}
	return syscall.UTF16ToString(buffer), nil
}

func registerDNSSubscribeSink(sink *dnsSubscribeSink) uintptr {
	if sink == nil {
		return 0
	}
	id := uintptr(atomic.AddUint64(&dnsSubscribeSeq, 1))
	dnsSubscribeSinks.Store(id, sink)
	return id
}

func unregisterDNSSubscribeSink(id uintptr) {
	if id == 0 {
		return
	}
	dnsSubscribeSinks.Delete(id)
}

func evtSubscribeCallback(action uintptr, userContext uintptr, event uintptr) uintptr {
	value, ok := dnsSubscribeSinks.Load(userContext)
	if !ok {
		return 0
	}
	sink, ok := value.(*dnsSubscribeSink)
	if !ok || sink == nil {
		return 0
	}

	switch action {
	case evtSubscribeActionDeliver:
		defer evtCloseHandle(event)
		xmlText, err := evtRenderXML(event)
		if err != nil {
			return 0
		}
		row, ok := parseDNSEventXML(xmlText)
		if !ok {
			return 0
		}
		select {
		case sink.rows <- row:
		default:
		}
	case evtSubscribeActionError:
		if event != 0 {
			err := fmt.Errorf("EvtSubscribe callback error: %w", syscall.Errno(event))
			select {
			case sink.errs <- err:
			default:
			}
		}
	}

	return 0
}

func evtCloseHandle(handle uintptr) {
	if handle == 0 {
		return
	}
	procEvtClose.Call(handle)
}

type dnsEventXML struct {
	System struct {
		EventID       uint32 `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		Execution     struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
		} `xml:"Execution"`
	} `xml:"System"`
	EventData struct {
		Data []dnsEventXMLData `xml:"Data"`
	} `xml:"EventData"`
}

type dnsEventXMLData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func parseDNSEventXML(raw string) (dnsEventRow, bool) {
	var event dnsEventXML
	if err := xml.Unmarshal([]byte(raw), &event); err != nil {
		return dnsEventRow{}, false
	}

	row := dnsEventRow{
		RecordID: event.System.EventRecordID,
		EventID:  event.System.EventID,
	}
	for _, data := range event.EventData.Data {
		name := strings.TrimSpace(data.Name)
		value := strings.TrimSpace(data.Value)
		switch {
		case strings.EqualFold(name, "QueryName"):
			row.QueryName = value
		case strings.EqualFold(name, "ClientPID"),
			strings.EqualFold(name, "ClientPid"),
			strings.EqualFold(name, "ClientProcessId"),
			strings.EqualFold(name, "ProcessID"),
			strings.EqualFold(name, "ProcessId"):
			if pid, ok := parseEventPID(value); ok {
				row.ClientPID = pid
			}
		}
	}
	if row.ClientPID == 0 && event.System.Execution.ProcessID != 0 {
		row.ClientPID = event.System.Execution.ProcessID
	}
	if strings.TrimSpace(row.QueryName) == "" || row.ClientPID == 0 {
		return dnsEventRow{}, false
	}
	return row, true
}

func parseEventPID(value string) (uint32, bool) {
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, false
	}
	v = strings.TrimSuffix(v, ";")
	pid, err := strconv.ParseUint(v, 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(pid), true
}

func unwrapCallErr(err error) error {
	if err == nil {
		return syscall.Errno(0)
	}
	if errno, ok := err.(syscall.Errno); ok {
		if errno == 0 {
			return syscall.Errno(0)
		}
		return errno
	}
	return err
}

func runPowerShell(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	script = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8; " + script

	cmd := exec.CommandContext(
		ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		script,
	)
	hideCommandWindow(cmd)

	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("powershell command timed out")
	}
	if err != nil {
		if trimmed == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, trimmed)
	}
	return trimmed, nil
}

func hideCommandWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
}
