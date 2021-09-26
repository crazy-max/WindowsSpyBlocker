//go:build windows
// +build windows

//go:generate go install github.com/kevinburke/go-bindata/go-bindata
//go:generate go-bindata -pkg bindata -o app/bindata/bindata.go app/settings.json data/... app.conf
//go:generate go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo
//go:generate goversioninfo -icon=.res/app.ico -manifest=app.manifest

package main

import (
	"fmt"

	"github.com/akyoto/color"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/telemetry"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/app"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/windows"
	"github.com/mcuadros/go-version"
)

func init() {
	windows.SetConsoleTitle(fmt.Sprintf("%s %s", config.AppName, config.AppVersion))
}

func main() {
	color.New(color.FgHiWhite).Println(config.AppName + " " + config.AppVersion)
	color.New(color.FgHiWhite).Println(config.AppURL)

	latestVersion, err := app.GetLatestVersion()
	if err != nil {
		color.New(color.FgRed).Printf("\n%s can't contact the update server: %s", config.AppName, err.Error())
	} else if version.Compare(config.AppVersion, latestVersion, "<") {
		color.New(color.FgHiGreen).Print("\nA new release is available : ")
		color.New(color.FgHiGreen, color.Bold).Print(latestVersion)
		color.New(color.FgHiGreen).Print("\nDownload : ")
		color.New(color.FgHiGreen, color.Bold).Print(config.AppURL + "/releases/latest\n")
	}

	menuCommands := []menu.CommandOption{
		{
			Description: "> Telemetry : Block telemetry and data collection",
			Color:       color.FgYellow,
			Function:    telemetry.Menu,
		},
		{
			Description: "> Dev       : Several tools used by WindowsSpyBlocker",
			Color:       color.FgYellow,
			Function:    dev.Menu,
		},
	}

	menuOptions := menu.NewOptions("Main", "'menu' for help [main]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
}
