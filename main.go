package main

import (
	"embed"
	"log"

	"github.com/LRJ217/net-evidence/internal/history"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	historyDir, err := history.DefaultDir()
	if err != nil {
		log.Fatal(err)
	}
	app := NewApp(historyDir)
	err = wails.Run(&options.App{
		Title:     "NetEvidence",
		Width:     1180,
		Height:    820,
		MinWidth:  900,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Bind:       []interface{}{app},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
	})
	if err != nil {
		log.Fatal(err)
	}
}
