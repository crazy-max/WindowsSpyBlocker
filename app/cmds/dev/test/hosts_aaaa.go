package test

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/ip6"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/akyoto/color"
)

func testHostsAAAALookup(args ...string) error {
	logsPath := path.Join(pathu.Logs)
	if err := file.CreateSubfolder(logsPath); err != nil {
		print.Error(err)
		return nil
	}

	defer timeu.Track(time.Now())
	testHostsAAAALookupByRule(data.RULES_EXTRA)
	testHostsAAAALookupByRule(data.RULES_SPY)
	testHostsAAAALookupByRule(data.RULES_UPDATE)

	fmt.Printf("\nLogs available in ")
	color.New(color.FgCyan).Printf("%s\n", strings.TrimLeft(logsPath, pathu.Current))

	return nil
}

func testHostsAAAALookupByRule(rule string) {
	fmt.Println()

	testCsv := path.Join(pathu.Logs, fmt.Sprintf("hosts-aaaa-test-%s.csv", rule))

	fmt.Printf("Get hosts for %s... ", rule)
	hosts, err := data.GetHostsByRule(rule)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	testCsvFile, _ := os.Create(testCsv)
	testCsvFile.WriteString("HOST,AAAA")
	for _, host := range hosts {
		fmt.Print("\nLookup AAAA for ")
		color.New(color.FgMagenta).Printf("%s", host.Domain)
		fmt.Print("...\n")
		testCsvFile.WriteString(fmt.Sprintf("\n%s", host.Domain))

		ip6Res := ip6.GetIP6(host.Domain)
		if ip6Res == (ip6.IP6{}) {
			color.New(color.FgRed).Println("Could not get AAAA record")
		} else {
			testCsvFile.WriteString(fmt.Sprintf(",%s", ip6Res.IP))
			color.New(color.FgCyan).Printf("AAAA: %s\n", ip6Res.IP)
		}
	}

	testCsvFile.Sync()
	testCsvFile.Close()
	fmt.Println()
}
