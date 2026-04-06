package appruntime

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"netch_go/internal/model"
)

type AssetLocator struct {
	Paths Paths
}

func NewAssetLocator(paths Paths) *AssetLocator {
	return &AssetLocator{Paths: paths}
}

func (l *AssetLocator) Resolve(name string) (string, bool) {
	for _, candidate := range l.candidates(name) {
		if fileExists(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func (l *AssetLocator) Inspect() []model.AssetCheck {
	names := []string{"Redirector.bin", "nfapi.dll", "nfdriver.sys"}
	result := make([]model.AssetCheck, 0, len(names))
	for _, name := range names {
		path, ok := l.Resolve(name)
		status := "missing"
		message := "未找到可用文件"
		if ok {
			status = "ready"
			message = "已就绪"
		}
		result = append(result, model.AssetCheck{Name: name, Path: path, Status: status, Message: message})
	}
	return result
}

func (l *AssetLocator) PrepareRuntime() ([]string, error) {
	if err := l.Paths.Ensure(); err != nil {
		return nil, err
	}

	actions := []string{}
	root := l.Paths.RootDir

	if copied, err := tryCopyFirst(
		[]string{
			filepath.Join(root, "Redirector", "bin", "Release", "Redirector.bin"),
			filepath.Join(root, "Redirector", "bin", "Debug", "Redirector.bin"),
		},
		filepath.Join(l.Paths.RuntimeBinDir, "Redirector.bin"),
	); err != nil {
		return actions, err
	} else if copied {
		actions = append(actions, "copied Redirector.bin")
	}

	if copied, err := tryCopyFirst(
		[]string{
			filepath.Join(root, "Redirector", "bin", "Release", "nfapi.dll"),
			filepath.Join(root, "Redirector", "bin", "Debug", "nfapi.dll"),
			filepath.Join(root, "Redirector", "static", "nfapi.dll"),
		},
		filepath.Join(l.Paths.RuntimeBinDir, "nfapi.dll"),
	); err != nil {
		return actions, err
	} else if copied {
		actions = append(actions, "copied nfapi.dll")
	}

	if copied, err := tryCopyFirst(
		[]string{
			filepath.Join(root, "nfdriver.sys"),
			filepath.Join(root, "Storage", "nfdriver.sys"),
			filepath.Join(root, "Redirector", "static", "nfdriver.sys"),
		},
		filepath.Join(l.Paths.RuntimeBinDir, "nfdriver.sys"),
	); err != nil {
		return actions, err
	} else if copied {
		actions = append(actions, "copied nfdriver.sys")
	}

	legacyModeDir := filepath.Join(root, "Storage", "mode")
	if dirExists(legacyModeDir) {
		target := l.Paths.RuntimeRulesDir
		if err := copyProcessRuleTree(legacyModeDir, target); err != nil {
			return actions, err
		}
		actions = append(actions, "merged process rule files")
	}

	return model.UniqueNonEmpty(actions), nil
}

func (l *AssetLocator) candidates(name string) []string {
	root := l.Paths.RootDir
	runtimePaths := map[string]string{
		"Redirector.bin": filepath.Join(l.Paths.RuntimeBinDir, "Redirector.bin"),
		"nfapi.dll":      filepath.Join(l.Paths.RuntimeBinDir, "nfapi.dll"),
		"nfdriver.sys":   filepath.Join(l.Paths.RuntimeBinDir, "nfdriver.sys"),
	}

	result := []string{runtimePaths[name]}
	switch name {
	case "Redirector.bin":
		result = append(result,
			filepath.Join(root, "Redirector", "bin", "Release", name),
			filepath.Join(root, "Redirector", "bin", "Debug", name),
		)
	case "nfapi.dll":
		result = append(result,
			filepath.Join(root, "Redirector", "bin", "Release", name),
			filepath.Join(root, "Redirector", "bin", "Debug", name),
			filepath.Join(root, "Redirector", "static", name),
		)
	case "nfdriver.sys":
		result = append(result,
			filepath.Join(root, name),
			filepath.Join(root, "Storage", name),
			filepath.Join(root, "Redirector", "static", name),
		)
	}
	return result
}

func tryCopyFirst(sources []string, target string) (bool, error) {
	for _, source := range sources {
		if !fileExists(source) {
			continue
		}
		if samePath(source, target) {
			return false, nil
		}
		if err := copyFile(source, target); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
}

func copyFile(source, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(target)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Close()
}

func copyProcessRuleTree(sourceRoot, targetRoot string) error {
	return filepath.WalkDir(sourceRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.EqualFold(d.Name(), "TUNTAP") {
			return filepath.SkipDir
		}

		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		target := filepath.Join(targetRoot, relative)

		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".json" {
			return nil
		}
		if !isProcessRuleFile(path, ext) {
			return nil
		}
		return copyFile(path, target)
	})
}

func isProcessRuleFile(path, ext string) bool {
	switch ext {
	case ".json":
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		var payload struct {
			Type any `json:"type"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return false
		}
		return isProcessModeType(payload.Type)
	default:
		return false
	}
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

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
