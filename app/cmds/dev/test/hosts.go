package test

import (
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/akyoto/color"
)

func testHostsLookup(args ...string) error {
	logsPath := path.Join(pathu.Logs)
	if err := file.CreateSubfolder(logsPath); err != nil {
		print.Error(err)
		return nil
	}

	defer timeu.Track(time.Now())
	testHostsLookupByRule(data.RULES_EXTRA)
	testHostsLookupByRule(data.RULES_SPY)
	testHostsLookupByRule(data.RULES_UPDATE)

	fmt.Printf("\nLogs available in ")
	color.New(color.FgCyan).Printf("%s\n", strings.TrimLeft(logsPath, pathu.Current))

	return nil
}

func testHostsLookupByRule(rule string) {
	fmt.Println()

	testCsv := path.Join(pathu.Logs, fmt.Sprintf("hosts-test-%s.csv", rule))

	fmt.Printf("Get hosts for %s... ", rule)
	hosts, err := data.GetHostsByRule(rule)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	testCsvFile, _ := os.Create(testCsv)
	testCsvFile.WriteString("HOST,IP ADRESSES")
	for _, host := range hosts {
		fmt.Print("\nLookup ")
		color.New(color.FgMagenta).Printf("%s", host.Domain)
		fmt.Print("...\n")
		testCsvFile.WriteString(fmt.Sprintf("\n%s", host.Domain))

		count := 0
		lIps, err := net.LookupIP(host.Domain)
		if err != nil {
			color.New(color.FgRed).Println("Could not get IPs")
		} else {
			for _, lIp := range lIps {
				if count == 0 {
					testCsvFile.WriteString(fmt.Sprintf(",%s", lIp.String()))
					count++
				} else {
					testCsvFile.WriteString(fmt.Sprintf("\n,%s", lIp.String()))
				}
				color.New(color.FgCyan).Printf("IP: %s\n", lIp.String())
			}
		}

		lCname, err := net.LookupCNAME(host.Domain)
		if err != nil {
			color.New(color.FgRed).Println("Could not get CNAME")
		} else {
			if count == 0 {
				testCsvFile.WriteString(fmt.Sprintf(",%s", lCname))
				count++
			} else {
				testCsvFile.WriteString(fmt.Sprintf("\n,%s", lCname))
			}
			color.New(color.FgCyan).Printf("CNAME: %s\n", lCname)
		}

		lNss, err := net.LookupNS(host.Domain)
		if err != nil {
			color.New(color.FgRed).Println("Could not get NS")
		} else {
			for _, lNs := range lNss {
				if count == 0 {
					testCsvFile.WriteString(fmt.Sprintf(",%s", lNs.Host))
					count++
				} else {
					testCsvFile.WriteString(fmt.Sprintf("\n,%s", lNs.Host))
				}
				color.New(color.FgCyan).Printf("NS: %s\n", lNs.Host)
			}
		}
	}

	testCsvFile.Sync()
	testCsvFile.Close()
	fmt.Println()
}
