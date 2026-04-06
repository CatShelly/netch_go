package main

import (
	"embed"
	"fmt"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app, err := NewApp()
	if err != nil {
		panic(err)
	}

	err = wails.Run(&options.App{
		Title:            "Netch Go",
		Width:            1200,
		Height:           760,
		MinWidth:         960,
		MinHeight:        620,
		BackgroundColour: &options.RGBA{R: 244, G: 238, B: 228, A: 1},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.Startup,
		OnDomReady:       app.DomReady,
		OnBeforeClose:    app.BeforeClose,
		OnShutdown:       app.Shutdown,
		Bind:             []interface{}{app},
	})
	if err != nil {
		fmt.Println("启动失败:", err.Error())
	}
}
