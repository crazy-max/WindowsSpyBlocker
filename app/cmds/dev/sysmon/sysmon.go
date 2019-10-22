package sysmon

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/app"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/cmd"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/akyoto/color"
)

// Menu of Sysmon
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Install",
			Color:       color.FgHiYellow,
			Function:    install,
		},
		{
			Description: "Uninstall",
			Color:       color.FgHiYellow,
			Function:    uninstall,
		},
		{
			Description: "Extract event log",
			Color:       color.FgHiYellow,
			Function:    extractEventLog,
		},
	}

	menuOptions := menu.NewOptions("Sysmon", "'menu' for help [dev-sysmon]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func init() {
	config.Settings.Libs.Sysmon.Dest = path.Join(pathu.Libs, "sysmon.zip")
	config.Settings.Libs.Sysmon.OutputPath = path.Join(pathu.Libs, "sysmon")
	config.Settings.Libs.Sysmon.Checkfile = path.Join(pathu.Libs, config.Settings.Libs.Sysmon.Checkfile)
}

func install(args ...string) (err error) {
	fmt.Println()

	if err := app.DownloadLib(config.Settings.Libs.Sysmon); err != nil {
		return nil
	}

	fmt.Print("Installing Sysmon... ")

	cmdResult, err := cmd.Exec(cmd.Options{
		Command: path.Join(config.Settings.Libs.Sysmon.OutputPath, "Sysmon.exe"),
		Args:    []string{"-i", "-accepteula", "-h", "md5", "-n", "-l"},
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	// Sysmon already installed not redir to stderr but stdout...
	if cmdResult.ExitCode == 1242 {
		print.ErrorStr(fmt.Sprintf("%d", cmdResult.ExitCode))
		if len(cmdResult.Stdout) > 0 {
			print.ErrorStr(fmt.Sprintf("%s\n", cmdResult.Stdout))
		} else {
			fmt.Print("\n")
		}
		return nil
	}

	if cmdResult.ExitCode != 0 {
		print.ErrorStr(fmt.Sprintf("%d", cmdResult.ExitCode))
		if len(cmdResult.Stderr) > 0 {
			print.ErrorStr(fmt.Sprintf("%s\n", cmdResult.Stderr))
		} else {
			fmt.Print("\n")
		}
		return nil
	}

	print.Ok()
	if len(cmdResult.Stdout) > 0 {
		fmt.Println(cmdResult.Stdout)
	}

	// Set log max size to 2GB
	// https://technet.microsoft.com/en-us/library/cc748849%28v=ws.11%29.aspx
	maxLogSize := "2147483648"
	fmt.Printf("Setting max log size to %s bytes... ", maxLogSize)
	cmdResult, err = cmd.Exec(cmd.Options{
		Command: "wevtutil.exe",
		Args:    []string{"sl", "Microsoft-Windows-Sysmon/Operational", "/ms:" + maxLogSize},
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	if cmdResult.ExitCode != 0 {
		print.ErrorStr(fmt.Sprintf("%d", cmdResult.ExitCode))
		if len(cmdResult.Stderr) > 0 {
			print.ErrorStr(fmt.Sprintf("%s\n", cmdResult.Stderr))
		}
		return nil
	}

	print.Ok()
	return nil
}

func uninstall(args ...string) (err error) {
	fmt.Println()

	if err := app.DownloadLib(config.Settings.Libs.Sysmon); err != nil {
		return nil
	}

	fmt.Print("Uninstalling Sysmon... ")
	cmdResult, err := cmd.Exec(cmd.Options{
		Command: path.Join(config.Settings.Libs.Sysmon.OutputPath, "Sysmon.exe"),
		Args:    []string{"-u", "-accepteula"},
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	if cmdResult.ExitCode != 0 {
		print.Error(fmt.Errorf("%d\n", cmdResult.ExitCode))
		if len(cmdResult.Stderr) > 0 {
			print.Error(fmt.Errorf("%s\n", cmdResult.Stderr))
		}
		return nil
	}

	print.Ok()
	if len(cmdResult.Stdout) > 0 {
		fmt.Println(cmdResult.Stdout)
	}

	evtxPath := path.Join(config.Settings.Sysmon.EvtxPath)
	fmt.Printf("Removing %s... ", evtxPath)
	if err := file.RemoveFile(evtxPath); err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()

	return nil
}

func extractEventLog(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	var eventsAll EventsSortDate
	var eventsUnique EventsSortDate
	var eventsHostsCount EventsSortHost

	fmt.Printf("Seeking %s... ", config.App.Sysmon.EvtxPath)
	if _, err := os.Stat(config.App.Sysmon.EvtxPath); err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()

	fmt.Print("Extracting events... ")
	evtxFile, err := os.Open(config.App.Sysmon.EvtxPath)
	if err != nil {
		print.Error(err)
		return nil
	}
	defer evtxFile.Close()

	ef, err := evtx.New(evtxFile)
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()

	fmt.Println("Analyzing events...")
	lineCount := 0
	excluded := []EvtxData{}
	for e := range ef.FastEvents() {
		if !e.IsEventID("3") {
			continue
		}

		var eventx Evtx
		err = json.Unmarshal(evtx.ToJSON(e), &eventx)
		if err != nil {
			err = fmt.Errorf("Cannot unmarshall event: %s", err.Error())
			print.Error(err)
			return nil
		}

		lineCount++
		eventxData := eventx.Event.EventData

		eventIpv6, _ := strconv.ParseBool(eventxData.DestinationIsIpv6)
		if eventIpv6 {
			excluded = append(excluded, eventxData)
			continue
		}

		domain := ""
		if eventxData.DestinationHostname != "" {
			domain = app.GetFilteredIpOrDomain(eventxData.DestinationHostname)
			if domain == "" {
				excluded = append(excluded, eventxData)
				continue
			}
		}

		ip := ""
		if eventxData.DestinationIp != "" {
			ip = app.GetFilteredIpOrDomain(eventxData.DestinationIp)
			if ip == "" {
				excluded = append(excluded, eventxData)
				continue
			}
		}

		host := domain
		if host == "" {
			host = ip
		}

		eventDate, _ := time.Parse("2006-01-02 15:04:05.000", eventxData.UtcTime)
		eventPort, _ := strconv.Atoi(eventxData.DestinationPort)

		fmt.Println("Found", host)
		//color.New(color.FgCyan).Println(host)
		event := Event{
			Date:     eventDate,
			Process:  eventxData.Image,
			Protocol: eventxData.Protocol,
			Host:     host,
			Port:     eventPort,
			PortName: strings.TrimSpace(eventxData.DestinationPortName),
			Whois:    whois.GetWhois(host),
		}
		eventsAll = append(eventsAll, event)

		eventFound := false
		for i := range eventsHostsCount {
			if eventsHostsCount[i].Host == host {
				eventsHostsCount[i].Count++
				eventFound = true
				break
			}
		}
		if !eventFound {
			event.Count = 1
			eventsHostsCount = append(eventsHostsCount, event)
		}
	}

	fmt.Println()
	fmt.Print("Total lines: ")
	color.New(color.FgYellow).Printf("%d\n", lineCount)
	fmt.Print("Processed: ")
	color.New(color.FgGreen).Printf("%d", len(eventsAll))
	fmt.Print(" (")
	color.New(color.FgRed).Printf("%d", len(excluded))
	fmt.Print(" excluded)\n")

	if len(eventsAll) == 0 {
		fmt.Println("No event to process...")
		return nil
	}

	// Create eventsUnique based on eventsAll
	duplicates := make(map[string]string)
	for _, eventAll := range eventsAll {
		eventHash := sha1.New()
		eventHash.Write([]byte(eventAll.Process + eventAll.Protocol + eventAll.Host + eventAll.PortName))
		eventHashStr := base64.URLEncoding.EncodeToString(eventHash.Sum(nil))
		if _, ok := duplicates[eventHashStr]; ok {
			continue
		} else {
			duplicates[eventHashStr] = eventAll.Process + eventAll.Protocol + eventAll.Host + eventAll.PortName
		}
		eventsUnique = append(eventsUnique, eventAll)
	}

	// Generate and write events
	_writeCsvEventsDateFile("sysmon-all.csv", eventsAll)
	_writeCsvEventsDateFile("sysmon-unique.csv", eventsUnique)
	_writeCsvEventsHostFile("sysmon-hosts-count.csv", eventsHostsCount)

	return nil
}

func _writeCsvEventsDateFile(filename string, events EventsSortDate) {
	csvFile, _ := os.Create(path.Join(pathu.Logs, filename))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.WriteString("DATE,EXE,PROTOCOL,HOST,PORT,PORT_NAME,ORGANIZATION,COUNTRY")
	sort.Sort(events)
	for _, event := range events {
		csvFile.WriteString(fmt.Sprintf("\n%s,%s,%s,%s,%v,%s", event.Date.Format("2006-01-02 15:04:05"), event.Process, event.Protocol, event.Host, event.Port, event.PortName))
		if event.Whois != (whois.Whois{}) {
			csvFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvFile.WriteString(",,")
		}
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	if err := csvFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvFile.Close()
}

func _writeCsvEventsHostFile(filename string, events EventsSortHost) {
	csvFile, _ := os.Create(path.Join(pathu.Logs, filename))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.WriteString("HOST,COUNT,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN")
	sort.Sort(events)
	for _, event := range events {
		csvFile.WriteString(fmt.Sprintf("\n%s,%v", event.Host, event.Count))

		if event.Whois != (whois.Whois{}) {
			csvFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvFile.WriteString(",,")
		}

		dnsresList := dnsres.Resolutions{}
		if netu.IsValidIPv4(event.Host) {
			dnsresList = dnsres.GetDnsRes(event.Host)
		}
		if dnsresList.Len() > 0 {
			countRes := 0
			for _, res := range dnsresList {
				if countRes == 0 {
					csvFile.WriteString(fmt.Sprintf(",%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
				} else {
					csvFile.WriteString(fmt.Sprintf("\n,,,,%s,%s", res.LastResolved.Format("2006-01-02"), res.IpOrDomain))
				}
				countRes += 1
			}
		} else {
			csvFile.WriteString(",,")
		}
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.Sync()
	if err := csvFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	csvFile.Close()
}
