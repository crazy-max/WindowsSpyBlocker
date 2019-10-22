package test

import (
	"fmt"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"

	"github.com/akyoto/color"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
)

func findIncompatibleRules(args ...string) error {
	extraSubnet := getSubnetIPs(data.RULES_EXTRA)
	spySubnet := getSubnetIPs(data.RULES_SPY)
	updateSubnet := getSubnetIPs(data.RULES_UPDATE)

	compareWith(data.RULES_EXTRA, extraSubnet, data.RULES_SPY, spySubnet)
	compareWith(data.RULES_SPY, spySubnet, data.RULES_UPDATE, updateSubnet)
	compareWith(data.RULES_UPDATE, updateSubnet, data.RULES_EXTRA, extraSubnet)

	return nil
}

func compareWith(rule1 string, subnetIPs1 []string, rule2 string, subnetIPs2 []string) {
	fmt.Print("\nChecking ")
	color.New(color.FgMagenta).Printf("%s", rule1)
	fmt.Print(" against ")
	color.New(color.FgMagenta).Printf("%s", rule2)
	fmt.Print("...\n")
	for _, subnetIP1 := range subnetIPs1 {
		for _, subnetIP2 := range subnetIPs2 {
			if subnetIP1 == subnetIP2 {
				color.New(color.FgRed).Printf("  %s\n", subnetIP2)
			}
		}
	}
}

func getSubnetIPs(rule string) []string {
	var subnetIPs []string

	checkIPs, err := data.GetFirewallIpsByRule(rule)
	if err != nil {
		print.Error(err)
		return nil
	}
	for _, checkIP := range checkIPs {
		checkIPSp := strings.Split(checkIP.IP, ".")
		checkSubnet := checkIPSp[0] + "." + checkIPSp[1] + "." + checkIPSp[2]
		if !stringsu.InSlice(checkSubnet, subnetIPs) {
			subnetIPs = append(subnetIPs, checkSubnet)
		}
	}

	return subnetIPs
}
