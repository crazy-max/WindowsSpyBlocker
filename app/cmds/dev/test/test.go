package test

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/akyoto/color"
)

// Menu of Firewall
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Test firewall IPs",
			Color:       color.FgHiYellow,
			Function:    testFirewallIps,
		},
		{
			Description: "Test domains lookup",
			Color:       color.FgHiYellow,
			Function:    testHostsLookup,
		},
		{
			Description: "Test domains AAAA lookup",
			Color:       color.FgHiYellow,
			Function:    testHostsAAAALookup,
		},
		{
			Description: "Find incompatible rules",
			Color:       color.FgHiYellow,
			Function:    findIncompatibleRules,
		},
	}

	menuOptions := menu.NewOptions("Test", "'menu' for help [dev-test]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}
