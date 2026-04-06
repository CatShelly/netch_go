//go:build windows

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"netch_go/internal/model"
)

const (
	dnsClientOperationalLog = "Microsoft-Windows-DNS-Client/Operational"
	dnsCapturePollInterval  = 1200 * time.Millisecond
	dnsCaptureProcessTick   = 2 * time.Second
	dnsCapturePollBatch     = 2048
	dnsCaptureMaxDomains    = 200
	dnsCaptureBackfillSpan  = 20000
	dnsCapturePIDHoldTTL    = 90 * time.Second
)

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
	lastRecordID   uint64
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

	latestRecordID, err := queryLatestRecordID()
	if err != nil {
		return m.failEnable(fmt.Sprintf("读取 DNS Client ETW 游标失败: %v", err))
	}
	startRecordID := uint64(0)
	if latestRecordID > dnsCaptureBackfillSpan {
		startRecordID = latestRecordID - dnsCaptureBackfillSpan
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
	m.message = "DNS Client ETW 抓取已开启，正在按规则匹配进程过滤域名"
	m.lastRecordID = startRecordID
	m.cancel = cancel
	m.matcher = matcher
	m.domains = []string{}
	m.domainSet = map[string]struct{}{}
	m.pidMatchHint = map[uint32]pidMatchResult{}
	m.activePIDs = map[uint32]pidSeen{}
	status := m.statusLocked()
	m.mu.Unlock()

	m.logf("info", fmt.Sprintf("DNS Client ETW 抓取已开启：规则集=%s，已执行 flushdns，回溯窗口 RID>%d（latest=%d）", ruleSet.Name, startRecordID, latestRecordID))
	fmt.Printf("[DNSWatch] enabled: ruleSet=%s startRID>%d latest=%d\n", ruleSet.Name, startRecordID, latestRecordID)

	go m.pollOnce()
	go m.processScanOnce()
	go m.pollLoop(ctx)
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
	fmt.Printf("[DNSWatch] enable failed: %s\n", message)
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

func (m *DNSCaptureMonitor) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(dnsCapturePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.pollOnce()
		}
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
	known := make(map[uint32]pidSeen, len(m.activePIDs))
	for pid, info := range m.activePIDs {
		known[pid] = info
	}
	m.mu.Unlock()

	matchedNow := scanMatchedProcessHints(matcher)

	newLines := []string{}
	now := time.Now()
	m.mu.Lock()
	for pid, hint := range matchedNow {
		if old, exists := known[pid]; !exists || !strings.EqualFold(old.name, hint) {
			newLines = append(newLines, fmt.Sprintf("[DNSWatch][PID] matched pid=%d process=%s", pid, hint))
		}
		m.activePIDs[pid] = pidSeen{name: hint, seenAt: now}
	}
	for pid, info := range m.activePIDs {
		if now.Sub(info.seenAt) > dnsCapturePIDHoldTTL {
			delete(m.activePIDs, pid)
		}
	}
	m.mu.Unlock()

	for _, line := range newLines {
		fmt.Println(line)
	}
}

func (m *DNSCaptureMonitor) pollOnce() {
	m.mu.Lock()
	minRecordID := m.lastRecordID
	m.mu.Unlock()

	rows, err := queryDNSRowsAfter(minRecordID)
	if err != nil {
		m.logf("warn", fmt.Sprintf("读取 DNS Client ETW 事件失败: %v", err))
		fmt.Printf("[DNSWatch] ETW query error: %v\n", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	type domainHit struct {
		domain  string
		pid     uint32
		process string
	}
	newDomains := make([]domainHit, 0, len(rows))

	m.mu.Lock()
	for _, row := range rows {
		if row.RecordID > m.lastRecordID {
			m.lastRecordID = row.RecordID
		}

		pid := row.ClientPID
		if pid == 0 {
			continue
		}

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
		if !matched {
			continue
		}

		domain := normalizeDomain(row.QueryName)
		if domain == "" {
			continue
		}
		processHint := ""
		if len(processTexts) > 0 {
			processHint = processTexts[0]
		}
		newDomains = append(newDomains, domainHit{
			domain:  domain,
			pid:     pid,
			process: processHint,
		})
	}
	m.mu.Unlock()

	for _, hit := range newDomains {
		m.ingestDomains(hit.pid, hit.process, []string{hit.domain})
	}
}

func (m *DNSCaptureMonitor) ingestDomains(pid uint32, processHint string, domains []string) {
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
		if processHint != "" {
			m.logf("info", fmt.Sprintf("[DNSWatch][DOMAIN] %s (pid=%d, process=%s)", domain, pid, processHint))
		} else {
			m.logf("info", fmt.Sprintf("[DNSWatch][DOMAIN] %s (pid=%d)", domain, pid))
		}
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
	output, err := exec.Command("ipconfig", "/flushdns").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func queryLatestRecordID() (uint64, error) {
	out, err := runPowerShell(
		"$e = Get-WinEvent -LogName '" + dnsClientOperationalLog + "' -MaxEvents 1 -ErrorAction SilentlyContinue;" +
			"if ($null -eq $e) { '0' } else { [string]$e.RecordId }",
	)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(out)
	if value == "" {
		return 0, nil
	}
	recordID, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse record id failed: %w", err)
	}
	return recordID, nil
}

func queryDNSRowsAfter(minRecordID uint64) ([]dnsEventRow, error) {
	script := fmt.Sprintf(`
$min = [UInt64]%d
$events = Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction SilentlyContinue
$events = @($events | Sort-Object RecordId)
$rows = @()
foreach($e in @($events)){
  try{
    [UInt64]$rid = [UInt64]$e.RecordId
    if($rid -le $min){ continue }
    $xml = [xml]$e.ToXml()
    $query = $null
    $clientPidVal = [UInt32]0
    foreach($d in @($xml.Event.EventData.Data)){
      if($d.Name -eq 'QueryName'){ $query = [string]$d.'#text' }
      if($d.Name -eq 'ClientPID'){
        [UInt32]$tmp = 0
        if([UInt32]::TryParse([string]$d.'#text', [ref]$tmp)){ $clientPidVal = $tmp }
      }
    }
    if([string]::IsNullOrWhiteSpace($query)){ continue }
    if($clientPidVal -le 0){ continue }
    $rows += [pscustomobject]@{
      recordId=$rid
      eventId=[UInt32]$e.Id
      queryName=$query
      clientPid=$clientPidVal
    }
  } catch {}
}
@($rows) | ConvertTo-Json -Compress
`, minRecordID, dnsClientOperationalLog, dnsCapturePollBatch)

	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}
	return decodeDNSRows(out)
}

func decodeDNSRows(raw string) ([]dnsEventRow, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return []dnsEventRow{}, nil
	}

	if strings.HasPrefix(trimmed, "{") {
		var row dnsEventRow
		if err := json.Unmarshal([]byte(trimmed), &row); err != nil {
			return nil, err
		}
		return []dnsEventRow{row}, nil
	}

	var rows []dnsEventRow
	if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
		return nil, err
	}
	return rows, nil
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
