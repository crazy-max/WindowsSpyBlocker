package proxifier

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cevaris/ordered_map"
	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/app"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/akyoto/color"
)

// Menu of Proxifier
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Extract log",
			Color:       color.FgHiYellow,
			Function:    extractLog,
		},
	}

	menuOptions := menu.NewOptions("Proxifier", "'menu' for help [dev-proxifier]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func extractLog(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	var eventsAll EventsSortDate
	var eventsUnique EventsSortDate
	var eventsHostsCount EventsSortHost

	fmt.Printf("Opening %s... ", config.App.Proxifier.LogPath)
	logFile, err := os.Open(config.App.Proxifier.LogPath)
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()
	defer logFile.Close()

	fmt.Printf("Reading %s... ", config.App.Proxifier.LogPath)
	fileBuf, err := ioutil.ReadFile(config.App.Proxifier.LogPath)
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()

	fmt.Print("Cleaning lines... ")
	rawLines := _cleanLines(string(fileBuf))
	print.Ok()

	nbLines := 0
	excluded := []string{}

	fmt.Println("Extracting events...")
	strBuf := bytes.NewBufferString(rawLines)
	for {
		line, err := strBuf.ReadString('\n')
		if len(line) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				}
				print.ErrorStr(fmt.Sprintf("\nError while reading: %s", err.Error()))
				return nil
			}
		}

		nbLines++
		if !_isValidLine(line) {
			excluded = append(excluded, line)
			continue
		}

		sLine := strings.Split(strings.TrimSpace(line), " ")
		if len(sLine) < 4 {
			excluded = append(excluded, line)
			continue
		}

		//print.Pretty(sLine)
		host := _getFilteredDomain(sLine)
		if host == "" {
			excluded = append(excluded, line)
			continue
		}

		logDateStr := strings.TrimPrefix(sLine[0], "[") + " " + strings.TrimSuffix(sLine[1], "]")
		logDate, _ := time.Parse("2006.01.02 15:04:05", logDateStr)
		logPid, _ := strconv.Atoi(sLine[3])

		logAccount := ""
		if len(sLine) == 6 {
			logAccount = sLine[4]
		}

		fmt.Println("Found", host)
		//color.New(color.FgCyan).Println(host)
		event := Event{
			Date:    logDate,
			Exe:     sLine[2],
			Pid:     logPid,
			Account: logAccount,
			Host:    host,
			Whois:   whois.GetWhois(host),
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
	color.New(color.FgYellow).Printf("%d\n", nbLines)
	fmt.Print("Processed: ")
	color.New(color.FgGreen).Printf("%d", len(eventsAll))
	fmt.Print(" (")
	color.New(color.FgRed).Printf("%d", len(excluded))
	fmt.Print(" excluded)\n")

	if len(eventsAll) == 0 {
		fmt.Println("No log to process...")
		return nil
	}

	// Create eventsUnique based on eventsAll
	duplicates := make(map[string]string)
	for _, eventAll := range eventsAll {
		logHash := sha1.New()
		logHash.Write([]byte(eventAll.Exe + eventAll.Account + eventAll.Host))
		logHashStr := base64.URLEncoding.EncodeToString(logHash.Sum(nil))
		if _, ok := duplicates[logHashStr]; ok {
			continue
		} else {
			duplicates[logHashStr] = eventAll.Exe + eventAll.Account + eventAll.Host
		}
		eventsUnique = append(eventsUnique, eventAll)
	}

	// Generate and write events
	_writeCsvEventsDateFile("proxifier-all.csv", eventsAll)
	_writeCsvEventsDateFile("proxifier-unique.csv", eventsUnique)
	_writeCsvEventsHostFile("proxifier-hosts-count.csv", eventsHostsCount)

	return nil
}

func _cleanLines(lines string) string {
	regexps := ordered_map.NewOrderedMap()
	regexps.Set(`matching(.*?)rule`, "")
	regexps.Set(`open\sdirectly`, "")
	regexps.Set(`Profile(.*?)loaded`, "")
	regexps.Set(`\:\sdirect\sconnection`, "")
	regexps.Set(`\:\sconnection\sblocked`, "")
	regexps.Set(`\serror\s\:\sA\sconnection\srequest\swas\scanceled(.*?)$`, "")
	regexps.Set(`\serror\s\:\sCould\snot\sconnect(.*?)$`, "")
	regexps.Set(`\:\sDNS`, "")
	regexps.Set(`\(According\sto\sRules\)`, "")
	regexps.Set(`GetSockName\s\:(.*?)$`, "")
	regexps.Set(`close(.*?)bytes(.*?)sent(.*?)received(.*?)lifetime(.*?)$`, "")
	regexps.Set(`resolve\s`, "")
	regexps.Set(`\*64\s`, "")
	regexps.Set(`Error\:\sWindows\snetwork\s\(Winsock\)\sis\snot\sproperly\sconfigured(.*?)$`, "")
	regexps.Set(`Proxifier\sor\ssome\sof\sits\sparts\smay\swork\sincorrectly(.*?)$`, "")
	regexps.Set(`It\sis\shighly\srecommended\sthat\syou\srun\sSysSettings\stool(.*?)$`, "")
	regexps.Set(`Windows\snetwork\swas\ssuccessfully\sconfigured(.*?)$`, "")
	regexps.Set(`\s-\s`, " ")
	regexps.Set(`\((\d+),\s(.*?)\)`, "$1 $2")
	regexps.Set(`\((\d+)\)`, "$1")

	iter := regexps.IterFunc()
	for kv, ok := iter(); ok; kv, ok = iter() {
		re := regexp.MustCompile(`(?mi)` + fmt.Sprintf("%v", kv.Key))
		lines = re.ReplaceAllString(strings.TrimSpace(lines), fmt.Sprintf("%v", kv.Value))
	}

	return lines
}

func _isValidLine(line string) bool {
	for _, unvalid := range config.Settings.Proxifier.UnvalidLines {
		if strings.Contains(line, unvalid) {
			return false
		}
	}

	if strings.HasSuffix("loaded.", line) {
		return false
	}

	return true
}

func _getFilteredDomain(sLine []string) string {
	domain := strings.TrimRight(sLine[len(sLine)-1], ".")
	if strings.Contains(domain, ":") {
		sHost := strings.Split(domain, ":")
		domain = sHost[0]
	}

	if strings.Contains(domain, `\`) {
		return ""
	}

	return app.GetFilteredIpOrDomain(domain)
}

func _writeCsvEventsDateFile(filename string, events EventsSortDate) {
	csvFile, _ := os.Create(path.Join(pathu.Logs, filename))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.WriteString("DATE,EXE,PID,ACCOUNT,HOST,ORGANIZATION,COUNTRY")
	sort.Sort(events)
	for _, event := range events {
		csvFile.WriteString(fmt.Sprintf("\n%s,%s,%v,%s,%s", event.Date.Format("2006-01-02 15:04:05"), event.Exe, event.Pid, event.Account, event.Host))
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
