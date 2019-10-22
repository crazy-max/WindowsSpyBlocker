package telemetry

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/telemetry/firewall"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/telemetry/ncsi"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/akyoto/color"
)

// Menu of Telemetry
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "> Firewall  : Add or remove firewall rules and resolve IPs adresses",
			Color:       color.FgYellow,
			Function:    firewall.Menu,
		},
		{
			Description: "> NCSI      : Apply an alternate NCSI and test your internet connection the Microsoft way",
			Color:       color.FgYellow,
			Function:    ncsi.Menu,
		},
	}

	menuOptions := menu.NewOptions("Telemetry", "'menu' for help [telemetry]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}
