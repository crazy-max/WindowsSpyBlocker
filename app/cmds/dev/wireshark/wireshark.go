package wireshark

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/dnsres"
	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/app"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/cmd"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/windows"
	"github.com/crazy-max/WindowsSpyBlocker/app/whois"
	"github.com/akyoto/color"
)

// Menu of Wireshark
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Install Npcap",
			Color:       color.FgHiYellow,
			Function:    installNpcap,
		},
		{
			Description: "Print list of network interfaces",
			Color:       color.FgHiYellow,
			Function:    printInterfaces,
		},
		{
			Description: "Capture (required Npcap)",
			Color:       color.FgHiYellow,
			Function:    capture,
		},
		{
			Description: "Extract log",
			Color:       color.FgHiYellow,
			Function:    extractLog,
		},
	}

	menuOptions := menu.NewOptions("Wireshark", "'menu' for help [dev-wireshark]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

var (
	wiresharkLib config.Lib
)

func init() {
	if windows.Is64Arch() {
		wiresharkLib = config.Settings.Libs.Wireshark64
	} else {
		wiresharkLib = config.Settings.Libs.Wireshark32
	}
	wiresharkLib.Dest = path.Join(pathu.Libs, "wireshark.zip")
	wiresharkLib.OutputPath = path.Join(pathu.Libs, "wireshark")
	wiresharkLib.Checkfile = path.Join(pathu.Libs, wiresharkLib.Checkfile)

	config.Settings.Libs.Npcap.Dest = path.Join(pathu.Libs, "npcap-setup.exe")
}

// https://rawgit.com/nmap/npcap/master/docs/npcap-guide-wrapper.html#npcap-redistribution-options
func installNpcap(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	fmt.Print("Checking if Npcap installed... ")
	if _, err := os.Stat(config.Settings.Libs.Npcap.Checkfile); err == nil {
		color.New(color.FgYellow).Print("Already installed\n")
		return nil
	}
	print.Ok()

	if err := app.DownloadLib(config.Settings.Libs.Npcap); err != nil {
		return nil
	}

	fmt.Print("Installing Npcap... ")
	cmdResult, err := cmd.Exec(cmd.Options{
		Command:    config.Settings.Libs.Npcap.Dest,
		Args:       []string{"/S", "/npf_startup=yes", "/loopback_support=yes", "/dlt_null=yes", "/winpcap_mode=yes"},
		HideWindow: true,
	})
	if err != nil {
		print.Error(err)
		return nil
	}
	if cmdResult.ExitCode != 0 {
		if len(cmdResult.Stderr) > 0 {
			print.Error(fmt.Errorf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stderr))
		} else {
			print.Error(fmt.Errorf("%d\n", cmdResult.ExitCode))
		}
		return nil
	}
	if _, err := os.Stat(config.Settings.Libs.Npcap.Checkfile); err != nil {
		print.Error(err)
		return err
	}
	print.Ok()

	return nil
}

func printInterfaces(args ...string) (err error) {
	fmt.Println()

	if err := app.DownloadLib(wiresharkLib); err != nil {
		return nil
	}

	fmt.Print("Getting network interfaces... ")
	results, err := _getNetworkInterfaces()
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()

	for _, result := range results {
		color.New(color.FgGreen).Printf("\n%d", result.ID)
		fmt.Print(" - ")
		color.New(color.FgYellow).Printf("%s", result.Name)
		fmt.Printf(" (%s)", result.Device)
	}

	fmt.Println()
	return nil
}

func capture(args ...string) (err error) {
	fmt.Println()
	outputPcapng := path.Join(pathu.Tmp, fmt.Sprintf("cap-%s.pcapng", time.Now().Format("20060102-150405")))

	if err := app.DownloadLib(wiresharkLib); err != nil {
		return nil
	}

	fmt.Print("Getting network interfaces... ")
	networkItfs, err := _getNetworkInterfaces()
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()

	networkItfSel := Interface{}
	fmt.Printf("Seeking network interface with ID = %d... ", config.App.Wireshark.Capture.Interface)
	if len(networkItfs) > 0 {
		for _, networkItf := range networkItfs {
			if networkItf.ID == config.App.Wireshark.Capture.Interface {
				networkItfSel = networkItf
				break
			}
		}
	}
	if networkItfSel == (Interface{}) {
		print.ErrorStr("Not found")
	}
	print.Ok()

	fmt.Println("\nTo stop the capture, press CTRL+D")

	/*fmt.Print("Starting capture on ")
	color.New(color.FgYellow).Printf("%s", networkItfSel.Name)
	fmt.Printf(" in %s...", strings.TrimLeft(outputPcapng, pathu.Current))*/
	command := exec.Command(path.Join(wiresharkLib.OutputPath, "dumpcap.exe"),
		"-i", strconv.Itoa(config.App.Wireshark.Capture.Interface),
		"-f", config.App.Wireshark.Capture.Filter,
		"-w", outputPcapng,
	)

	// Stdout
	command.Stdout = os.Stdout
	command.Stderr = os.Stdout

	// Stdin
	in, err := command.StdinPipe()
	if err != nil {
		print.Error(err)
		return nil
	}
	defer in.Close()

	// Start capture
	err = command.Start()
	if err != nil {
		print.Error(err)
		return nil
	}

	// Wait stop capture signal (CTRL+C)
	cSignal := make(chan os.Signal, 1)
	signal.Notify(cSignal, os.Interrupt)
	go func() {
		command.Process.Signal(os.Interrupt)
	}()

	err = command.Wait()
	if err != nil {
		print.Error(err)
		return nil
	}

	fmt.Println()
	return nil
}

func extractLog(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	var eventsAll Events
	var eventsHostsCount Events

	if err := app.DownloadLib(wiresharkLib); err != nil {
		return nil
	}

	fmt.Printf("Opening %s... ", config.App.Wireshark.PcapngPath)
	pcapngFile, err := os.Open(config.App.Wireshark.PcapngPath)
	if err != nil {
		print.Error(err)
		return nil
	}
	print.Ok()
	defer pcapngFile.Close()

	fmt.Print("Extracting events... ")
	cmdResult, err := cmd.Exec(cmd.Options{
		Command:    path.Join(wiresharkLib.OutputPath, "tshark.exe"),
		Args:       []string{"-r", config.App.Wireshark.PcapngPath, "-q", "-z", "ip_hosts,tree"},
		WorkingDir: wiresharkLib.OutputPath,
	})
	if err != nil {
		print.Error(err)
		return nil
	}

	if cmdResult.ExitCode != 0 {
		if len(cmdResult.Stderr) > 0 {
			print.Error(fmt.Errorf("%d\n%s\n", cmdResult.ExitCode, cmdResult.Stderr))
		} else {
			print.Error(fmt.Errorf("%d\n", cmdResult.ExitCode))
		}
		return nil
	}

	if len(cmdResult.Stdout) == 0 {
		print.Error(fmt.Errorf("No data found in %s\n", config.App.Wireshark.PcapngPath))
		return nil
	}
	print.Ok()

	lineCount := 0
	excluded := [][]string{}

	fmt.Println("Analyzing events...")
	//ioutil.WriteFile("wireshark.txt", []byte(cmdResult.Stdout), 0644)
	lines := strings.Split(cmdResult.Stdout, "\n")
	for _, line := range lines {
		values := strings.Split(stringsu.RemoveExtraSpaces(line), " ")
		if len(values) != 6 {
			continue
		}

		lineCount++

		// Exclude IPv6 and private network
		if !netu.IsValidIPv4(values[0]) || netu.IsPrivateIp(values[0]) {
			excluded = append(excluded, values)
			continue
		}

		fmt.Println("Found", values[0])
		countAll, _ := strconv.Atoi(values[1])
		eventsAll = append(eventsAll, Event{
			IP:     values[0],
			Count:  countAll,
			DnsRes: dnsres.GetDnsRes(values[0]),
			Whois:  whois.GetWhois(values[0]),
		})

		host := app.GetFilteredIpOrDomain(values[0])
		if host == "" {
			excluded = append(excluded, values)
			continue
		}

		count, _ := strconv.Atoi(values[1])

		//color.New(color.FgCyan).Println(host)
		eventsHostsCount = append(eventsHostsCount, Event{
			IP:     host,
			Count:  count,
			DnsRes: dnsres.GetDnsRes(host),
			Whois:  whois.GetWhois(host),
		})
	}

	fmt.Println()
	fmt.Print("Total lines: ")
	color.New(color.FgYellow).Printf("%d\n", lineCount)
	fmt.Print("All processed: ")
	color.New(color.FgGreen).Printf("%d\n", len(eventsAll))
	fmt.Print("Processed: ")
	color.New(color.FgGreen).Printf("%d", len(eventsHostsCount))
	fmt.Print(" (")
	color.New(color.FgRed).Printf("%d", len(excluded))
	fmt.Print(" excluded)\n")

	if len(eventsHostsCount) == 0 {
		fmt.Println("No event to process...")
		return nil
	}

	// Generate and write file
	_writeCsvEventsHostFile("wireshark-all.csv", eventsAll)
	_writeCsvEventsHostFile("wireshark-hosts-count.csv", eventsHostsCount)

	return nil
}

func _writeCsvEventsHostFile(filename string, events Events) {
	csvFile, _ := os.Create(path.Join(pathu.Logs, filename))
	fmt.Printf("\nGenerating %s... ", strings.TrimLeft(csvFile.Name(), pathu.Current))
	csvFile.WriteString("HOST,COUNT,ORGANIZATION,COUNTRY,RESOLVED DATE,RESOLVED DOMAIN")
	sort.Sort(events)
	for _, event := range events {
		csvFile.WriteString(fmt.Sprintf("\n%s,%v", event.IP, event.Count))

		if event.Whois != (whois.Whois{}) {
			csvFile.WriteString(fmt.Sprintf(",%s,%s", event.Whois.Org, event.Whois.Country))
		} else {
			csvFile.WriteString(",,")
		}

		if len(event.DnsRes) > 0 {
			countRes := 0
			for _, res := range event.DnsRes {
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

func _getNetworkInterfaces() (Interfaces, error) {
	var interfaces Interfaces

	cmdResult, err := cmd.Exec(cmd.Options{
		Command:    path.Join(wiresharkLib.OutputPath, "dumpcap.exe"),
		Args:       []string{"-D"},
		WorkingDir: wiresharkLib.OutputPath,
	})
	if err != nil {
		return nil, err
	}

	if cmdResult.ExitCode == 2 {
		return nil, errors.New("Npcap not installed")
	} else if cmdResult.ExitCode != 0 {
		if len(cmdResult.Stderr) > 0 {
			return nil, fmt.Errorf("%d\n%s", cmdResult.ExitCode, cmdResult.Stderr)
		}
		return nil, fmt.Errorf("%d", cmdResult.ExitCode)
	}

	if len(cmdResult.Stdout) == 0 {
		return nil, errors.New("No network interface found")
	}

	strBuf := bytes.NewBufferString(cmdResult.Stdout)
	for {
		line, err := strBuf.ReadString('\n')
		if len(line) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}
		}

		values := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(values) != 3 {
			continue
		}

		id, err := strconv.Atoi(strings.TrimRight(values[0], "."))
		if err != nil {
			return nil, err
		}

		interfaces = append(interfaces, Interface{
			ID:     id,
			Device: values[1],
			Name:   strings.TrimRight(strings.TrimLeft(values[2], "("), ")"),
		})
	}

	return interfaces, nil
}
