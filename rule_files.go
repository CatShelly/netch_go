package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netch_go/internal/model"
)

type runtimeRuleJSON struct {
	Type        any                 `json:"type"`
	Remark      any                 `json:"remark"`
	Description string              `json:"description"`
	Handle      []string            `json:"handle"`
	Bypass      []string            `json:"bypass"`
	Domains     []string            `json:"domains"`
	Redirector  *model.ProxyOptions `json:"redirector,omitempty"`
}

func (a *App) loadRuleSetsFromRuntime() ([]model.RuleSet, error) {
	root := a.paths.RuntimeRulesDir
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}

	a.mu.Lock()
	fallbackProxy := a.config.Proxy
	a.mu.Unlock()
	fallbackProxy.Normalize()

	items := make([]model.RuleSet, 0, 64)
	nameSeen := map[string]int{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if strings.EqualFold(d.Name(), "exclude") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".json") {
			return nil
		}

		payload, err := readRuntimeRuleJSON(path)
		if err != nil || !isProcessModeTypeRule(payload.Type) {
			return nil
		}

		name := pickRuleNameFromAny(payload.Remark, strings.TrimSuffix(d.Name(), filepath.Ext(d.Name())))
		if name == "" {
			return nil
		}
		nameSeen[name]++
		displayName := name
		if nameSeen[name] > 1 {
			displayName = fmt.Sprintf("%s (%d)", name, nameSeen[name])
		}

		item := model.RuleSet{
			ID:          ruleIDFromPath(root, path),
			Name:        displayName,
			Description: strings.TrimSpace(payload.Description),
			Source:      "rules",
			SourcePath:  path,
			Tag:         ruleTagFromPath(root, path),
			Include:     model.UniqueNonEmpty(payload.Handle),
			Exclude:     model.UniqueNonEmpty(payload.Bypass),
			DomainRules: model.UniqueNonEmpty(payload.Domains),
			Proxy:       fallbackProxy,
			ReadOnly:    false,
		}
		if payload.Redirector != nil {
			item.Proxy = *payload.Redirector
		}
		item.Normalize()
		item.ID = ruleIDFromPath(root, path)
		item.Source = "rules"
		item.SourcePath = path
		item.ReadOnly = false
		items = append(items, item)
		return nil
	})

	sort.Slice(items, func(i, j int) bool {
		tagI := strings.TrimSpace(items[i].Tag)
		tagJ := strings.TrimSpace(items[j].Tag)
		hasTagI := tagI != ""
		hasTagJ := tagJ != ""
		if hasTagI != hasTagJ {
			return hasTagI
		}
		if hasTagI && !strings.EqualFold(tagI, tagJ) {
			return strings.ToLower(tagI) < strings.ToLower(tagJ)
		}
		if items[i].Name == items[j].Name {
			return items[i].SourcePath < items[j].SourcePath
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items, nil
}

func readRuntimeRuleJSON(path string) (runtimeRuleJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeRuleJSON{}, err
	}
	payload := runtimeRuleJSON{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return runtimeRuleJSON{}, err
	}
	return payload, nil
}

func (a *App) upsertRuleSetFile(input model.RuleSet) (model.RuleSet, error) {
	root := a.paths.RuntimeRulesDir
	if err := os.MkdirAll(root, 0o755); err != nil {
		return model.RuleSet{}, err
	}

	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	input.Include = model.UniqueNonEmpty(input.Include)
	input.Exclude = model.UniqueNonEmpty(input.Exclude)
	input.DomainRules = model.UniqueNonEmpty(input.DomainRules)
	if isProxyOptionsUnset(input.Proxy) {
		a.mu.Lock()
		input.Proxy = a.config.Proxy
		a.mu.Unlock()
	}
	input.Proxy.Normalize()
	if input.Name == "" {
		return model.RuleSet{}, fmt.Errorf("规则名称不能为空")
	}

	existing, err := a.loadRuleSetsFromRuntime()
	if err != nil {
		return model.RuleSet{}, err
	}
	existingByID := map[string]model.RuleSet{}
	for _, item := range existing {
		existingByID[item.ID] = item
	}

	targetPath := ""
	if item, ok := existingByID[input.ID]; ok {
		targetPath = item.SourcePath
	}
	if targetPath == "" && strings.TrimSpace(input.SourcePath) != "" {
		clean := filepath.Clean(input.SourcePath)
		if strings.HasPrefix(strings.ToLower(clean), strings.ToLower(root)) {
			targetPath = clean
		}
	}
	if targetPath == "" {
		customRoot := filepath.Join(root, "custom")
		if err := os.MkdirAll(customRoot, 0o755); err != nil {
			return model.RuleSet{}, err
		}
		targetPath = nextAvailableRulePath(customRoot, input.Name)
	}

	payload := runtimeRuleJSON{
		Type:        "ProcessMode",
		Remark:      map[string]string{"zh-CN": input.Name},
		Description: input.Description,
		Handle:      input.Include,
		Bypass:      input.Exclude,
		Domains:     input.DomainRules,
		Redirector:  &input.Proxy,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return model.RuleSet{}, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return model.RuleSet{}, err
	}

	saved := model.RuleSet{
		ID:          ruleIDFromPath(root, targetPath),
		Name:        input.Name,
		Description: input.Description,
		Source:      "rules",
		SourcePath:  targetPath,
		Tag:         ruleTagFromPath(root, targetPath),
		Include:     input.Include,
		Exclude:     input.Exclude,
		DomainRules: input.DomainRules,
		Proxy:       input.Proxy,
		ReadOnly:    false,
	}
	saved.Normalize()
	saved.ID = ruleIDFromPath(root, targetPath)
	saved.Source = "rules"
	saved.SourcePath = targetPath
	saved.ReadOnly = false
	return saved, nil
}

func (a *App) deleteRuleSetFileByID(id string) (bool, error) {
	root := a.paths.RuntimeRulesDir
	items, err := a.loadRuleSetsFromRuntime()
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if item.ID != id {
			continue
		}
		clean := filepath.Clean(item.SourcePath)
		if !strings.HasPrefix(strings.ToLower(clean), strings.ToLower(root)) {
			return false, fmt.Errorf("规则路径不在 runtime/rules 下: %s", clean)
		}
		if err := os.Remove(clean); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func ruleIDFromPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(strings.ToLower(filepath.Clean(rel)))
	sum := sha1.Sum([]byte(rel))
	return "rule_" + hex.EncodeToString(sum[:8])
}

func nextAvailableRulePath(root, ruleName string) string {
	base := sanitizeRuleFileName(ruleName)
	target := filepath.Join(root, base+".json")
	if _, err := os.Stat(target); err != nil {
		return target
	}
	for i := 2; i < 10000; i++ {
		candidate := filepath.Join(root, fmt.Sprintf("%s-%d.json", base, i))
		if _, err := os.Stat(candidate); err != nil {
			return candidate
		}
	}
	return filepath.Join(root, fmt.Sprintf("rule-%d.json", time.Now().Unix()))
}

func ruleTagFromPath(root, path string) string {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	parent := filepath.Dir(path)
	if strings.EqualFold(parent, root) {
		return ""
	}
	tag := strings.TrimSpace(filepath.Base(parent))
	if tag == "." || tag == string(filepath.Separator) {
		return ""
	}
	return tag
}

func sanitizeRuleFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "rule"
	}
	invalid := `<>:"/\|?*`
	builder := strings.Builder{}
	for _, ch := range name {
		if ch < 32 || strings.ContainsRune(invalid, ch) {
			builder.WriteRune('_')
			continue
		}
		builder.WriteRune(ch)
	}
	result := strings.Trim(builder.String(), ". ")
	if result == "" {
		result = "rule"
	}
	if len([]rune(result)) > 80 {
		result = string([]rune(result)[:80])
	}
	return result
}

func isProxyOptionsUnset(proxy model.ProxyOptions) bool {
	return !proxy.FilterLoopback &&
		!proxy.FilterIntranet &&
		!proxy.FilterParent &&
		!proxy.FilterICMP &&
		!proxy.FilterTCP &&
		!proxy.FilterUDP &&
		!proxy.FilterDNS &&
		!proxy.HandleOnlyDNS &&
		!proxy.DNSProxy &&
		!proxy.DNSDomainOnly &&
		strings.TrimSpace(proxy.RemoteDNS) == "" &&
		proxy.ICMPDelay == 0
}

func isProcessModeTypeRule(value any) bool {
	switch typed := value.(type) {
	case float64:
		return int(typed) == 0
	case string:
		return strings.EqualFold(typed, "ProcessMode") || strings.EqualFold(typed, "0")
	default:
		return false
	}
}

func pickRuleNameFromAny(value any, fallback string) string {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{"zh-CN", "zh", "en", "default"} {
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
		for _, key := range []string{"zh-CN", "zh", "en", "default"} {
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
