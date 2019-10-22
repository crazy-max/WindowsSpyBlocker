package dev

import (
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/diff"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/proxifier"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/sysmon"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/test"
	"github.com/crazy-max/WindowsSpyBlocker/app/cmds/dev/wireshark"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/akyoto/color"
)

// Menu of Dev
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "> Proxifier  : Extract events from log file",
			Color:       color.FgYellow,
			Function:    proxifier.Menu,
		},
		{
			Description: "> Sysmon     : Install / uninstall Sysmon and extract events from EVTX file",
			Color:       color.FgYellow,
			Function:    sysmon.Menu,
		},
		{
			Description: "> Wireshark  : Extract events from PCAPNG file filtered by IPv4 hosts",
			Color:       color.FgYellow,
			Function:    wireshark.Menu,
		},
		{
			Description: "> Test       : Test firewall IPs and hosts lookup",
			Color:       color.FgYellow,
			Function:    test.Menu,
		},
		{
			Description: "> Diff       : Generates a diff log based on CSV data",
			Color:       color.FgYellow,
			Function:    diff.Menu,
		},
		{
			Description: "Merge        : Merge firewall and hosts data to multi format",
			Color:       color.FgHiYellow,
			Function:    merge,
		},
		{
			Description: "Extract data : Extract embedded data in the current folder",
			Color:       color.FgHiYellow,
			Function:    extractData,
		},
	}

	menuOptions := menu.NewOptions("Dev", "'menu' for help [dev]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}
