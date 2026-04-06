package appruntime

import (
	"os"
	"path/filepath"
	"strings"
)

type Paths struct {
	RootDir         string
	DataDir         string
	RuntimeDir      string
	RuntimeBinDir   string
	RuntimeDNSDir   string
	RuntimeRulesDir string
}

func DiscoverPaths() (Paths, error) {
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	root := pickRoot(exeDir, cwd)
	paths := Paths{
		RootDir:         root,
		DataDir:         filepath.Join(root, "data"),
		RuntimeDir:      filepath.Join(root, "runtime"),
		RuntimeBinDir:   filepath.Join(root, "runtime", "bin"),
		RuntimeDNSDir:   filepath.Join(root, "runtime", "dns"),
		RuntimeRulesDir: filepath.Join(root, "runtime", "rules"),
	}
	return paths, paths.Ensure()
}

func (p Paths) Ensure() error {
	for _, dir := range []string{p.DataDir, p.RuntimeDir, p.RuntimeBinDir, p.RuntimeDNSDir, p.RuntimeRulesDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func pickRoot(candidates ...string) string {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		if found, ok := findRootUpward(candidate); ok {
			return found
		}
	}

	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return "."
}

func findRootUpward(start string) (string, bool) {
	start = filepath.Clean(start)
	if start == "" {
		return "", false
	}

	dir := start
	for i := 0; i < 8; i++ {
		if hasProjectMarkers(dir) {
			return dir, true
		}

		parent := filepath.Dir(dir)
		if parent == dir || parent == "." || strings.TrimSpace(parent) == "" {
			break
		}
		dir = parent
	}

	return "", false
}

func hasProjectMarkers(dir string) bool {
	if fileExists(filepath.Join(dir, "wails.json")) && fileExists(filepath.Join(dir, "go.mod")) {
		return true
	}
	if dirExists(filepath.Join(dir, "runtime", "bin")) && dirExists(filepath.Join(dir, "runtime", "rules")) {
		return true
	}
	if dirExists(filepath.Join(dir, "runtime")) && fileExists(filepath.Join(dir, "main.go")) {
		return true
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
