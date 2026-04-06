package config

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "sync"

    "netch_go/internal/model"
    appruntime "netch_go/internal/runtime"
)

type Store struct {
    path string
    mu   sync.RWMutex
}

func NewStore(paths appruntime.Paths) *Store {
    return &Store{path: filepath.Join(paths.DataDir, "config.json")}
}

func (s *Store) Path() string {
    return s.path
}

func (s *Store) Load() (model.AppConfig, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    data, err := os.ReadFile(s.path)
    if errors.Is(err, os.ErrNotExist) {
        return model.DefaultConfig(), nil
    }
    if err != nil {
        return model.AppConfig{}, err
    }

    cfg := model.DefaultConfig()
    if err := json.Unmarshal(data, &cfg); err != nil {
        return model.AppConfig{}, err
    }
    cfg.Normalize()
    return cfg, nil
}

func (s *Store) Save(cfg model.AppConfig) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    cfg.Normalize()
    if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
        return err
    }

    data, err := json.MarshalIndent(cfg, "", "  ")
    if err != nil {
        return err
    }

    tmp := s.path + ".tmp"
    if err := os.WriteFile(tmp, data, 0o644); err != nil {
        return err
    }
    return os.Rename(tmp, s.path)
}
