//go:build !windows

package main

type noopTrayController struct{}

func newTrayController(app *App) trayController {
	_ = app
	return &noopTrayController{}
}

func (n *noopTrayController) Start() error { return nil }
func (n *noopTrayController) Stop()        {}
func (n *noopTrayController) IsReady() bool {
	return true
}
