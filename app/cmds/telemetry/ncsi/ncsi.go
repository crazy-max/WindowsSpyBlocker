package ncsi

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/menu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/windows"
	"github.com/akyoto/color"
	"github.com/miekg/dns"
	"golang.org/x/sys/windows/registry"
)

// Menu of NCSI
func Menu(args ...string) (err error) {
	menuCommands := []menu.CommandOption{
		{
			Description: "Display your current NCSI values",
			Color:       color.FgHiYellow,
			Function:    current,
		},
		{
			Description: "Apply WindowsSpyBlocker NCSI",
			Color:       color.FgHiYellow,
			Function:    wsb,
		},
		{
			Description: "Apply Microsoft NCSI",
			Color:       color.FgHiYellow,
			Function:    microsoft,
		},
		{
			Description: "Test the internet connection",
			Color:       color.FgHiYellow,
			Function:    test,
		},
	}

	menuOptions := menu.NewOptions("NCSI", "'menu' for help [telemetry-ncsi]> ", 0, "")

	menuN := menu.NewMenu(menuCommands, menuOptions)
	menuN.Start()
	return
}

func current(args ...string) error {
	fmt.Println()
	defer timeu.Track(time.Now())

	probe, err := getNcsi()
	if err != nil {
		print.Error(err)
		return nil
	}
	fmt.Print("Getting current registry values... ")
	print.Ok()

	fmt.Println()
	color.New(color.FgMagenta).Println("# Web Probe IPv4")
	print.RegString(config.Settings.Ncsi.Reg.WebProbeHost, probe.WebHostV4)
	print.RegString(config.Settings.Ncsi.Reg.WebProbePath, probe.WebPathV4)
	print.RegString(config.Settings.Ncsi.Reg.WebProbeContent, probe.WebContentV4)

	color.New(color.FgMagenta).Println("\n# Web Probe IPv6")
	print.RegString(config.Settings.Ncsi.Reg.WebProbeHostV6, probe.WebHostV6)
	print.RegString(config.Settings.Ncsi.Reg.WebProbePathV6, probe.WebPathV6)
	print.RegString(config.Settings.Ncsi.Reg.WebProbeContentV6, probe.WebContentV6)

	color.New(color.FgMagenta).Println("\n# DNS Probe IPv4")
	print.RegString(config.Settings.Ncsi.Reg.DnsProbeHost, probe.DnsHostV4)
	print.RegString(config.Settings.Ncsi.Reg.DnsProbeContent, probe.DnsContentV4)

	color.New(color.FgMagenta).Println("\n# DNS Probe IPv6")
	print.RegString(config.Settings.Ncsi.Reg.DnsProbeHostV6, probe.DnsHostV6)
	print.RegString(config.Settings.Ncsi.Reg.DnsProbeContentV6, probe.DnsContentV6)

	fmt.Println()
	return nil
}

func wsb(args ...string) (err error) {
	defer timeu.Track(time.Now())
	return setNcsi(config.Settings.Ncsi.Probes.Wsb)
}

func microsoft(args ...string) error {
	defer timeu.Track(time.Now())
	return setNcsi(config.Settings.Ncsi.Probes.Microsoft)
}

func test(args ...string) (err error) {
	fmt.Println()
	defer timeu.Track(time.Now())

	current, err := getNcsi()
	if err != nil {
		return nil
	}

	fmt.Println()
	fmt.Print("Testing web request IPv4... ")
	err = testHttpProbe("http://"+current.WebHostV4+"/"+current.WebPathV4, current.WebContentV4)
	if err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}

	fmt.Print("Testing web request IPv6... ")
	err = testHttpProbe("http://"+current.WebHostV6+"/"+current.WebPathV6, current.WebContentV6)
	if err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}

	fmt.Print("Testing DNS resolution IPv4... ")
	err = testDnsProbe(current.DnsHostV4, dns.TypeA, current.DnsContentV4)
	if err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}

	fmt.Print("Testing DNS resolution IPv6... ")
	err = testDnsProbe(current.DnsHostV6, dns.TypeAAAA, current.DnsContentV6)
	if err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}

	return nil
}

func getNcsi() (config.NcsiProbe, error) {
	key, err := windows.OpenRegKey(registry.LOCAL_MACHINE, config.Settings.Ncsi.Reg.Key, registry.QUERY_VALUE)
	if err != nil {
		return config.NcsiProbe{}, err
	}
	defer key.Close()

	return config.NcsiProbe{
		WebHostV4:    windows.GetRegString(key, config.Settings.Ncsi.Reg.WebProbeHost),
		WebPathV4:    windows.GetRegString(key, config.Settings.Ncsi.Reg.WebProbePath),
		WebContentV4: windows.GetRegString(key, config.Settings.Ncsi.Reg.WebProbeContent),
		WebHostV6:    windows.GetRegString(key, config.Settings.Ncsi.Reg.WebProbeHostV6),
		WebPathV6:    windows.GetRegString(key, config.Settings.Ncsi.Reg.WebProbePathV6),
		WebContentV6: windows.GetRegString(key, config.Settings.Ncsi.Reg.WebProbeContentV6),
		DnsHostV4:    windows.GetRegString(key, config.Settings.Ncsi.Reg.DnsProbeHost),
		DnsContentV4: windows.GetRegString(key, config.Settings.Ncsi.Reg.DnsProbeContent),
		DnsHostV6:    windows.GetRegString(key, config.Settings.Ncsi.Reg.DnsProbeHostV6),
		DnsContentV6: windows.GetRegString(key, config.Settings.Ncsi.Reg.DnsProbeContentV6),
	}, nil
}

func setNcsi(probe config.NcsiProbe) error {
	fmt.Println()

	key, err := windows.OpenRegKey(registry.LOCAL_MACHINE, config.Settings.Ncsi.Reg.Key, registry.WRITE)
	if err != nil {
		return nil
	}
	defer key.Close()

	if err = windows.SetRegString(key, config.Settings.Ncsi.Reg.WebProbeHost, probe.WebHostV4); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.WebProbePath, probe.WebPathV4); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.WebProbeContent, probe.WebContentV4); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.WebProbeHostV6, probe.WebHostV6); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.WebProbePathV6, probe.WebPathV6); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.WebProbeContentV6, probe.WebContentV6); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.DnsProbeHost, probe.DnsHostV4); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.DnsProbeContent, probe.DnsContentV4); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.DnsProbeHostV6, probe.DnsHostV6); err != nil {
		return nil
	}
	if err := windows.SetRegString(key, config.Settings.Ncsi.Reg.DnsProbeContentV6, probe.DnsContentV6); err != nil {
		return nil
	}

	fmt.Println()
	return nil
}

func testHttpProbe(url string, content string) error {
	response, err := http.Get(url)
	if err != nil {
		return err
	}

	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("HTTP status code %d", response.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	bodyString := string(bodyBytes)
	if bodyString != content {
		return fmt.Errorf("Invalid content '%s'. Expected '%s'", bodyString, content)
	}

	return nil
}

func testDnsProbe(host string, dnsType uint16, content string) error {
	ipType := "IPv4"
	if dnsType == dns.TypeAAAA {
		ipType = "IPv6"
	}

	dnsTypeStr := "A"
	if dnsType == dns.TypeAAAA {
		dnsTypeStr = "AAAA"
	}

	localc := new(dns.Client)
	localc.ReadTimeout = 5 * 1e9

	localm := new(dns.Msg)
	localm.RecursionDesired = true
	localm.SetQuestion(dns.Fqdn(host), dnsType)

	ra, _, err := localc.Exchange(localm, net.JoinHostPort(host, "53"))
	if ra == nil {
		return fmt.Errorf("Error getting the %s address of %s: %s", ipType, host, err.Error())
	}
	if ra.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Invalid answer name %s after %s query: %s", host, dnsTypeStr, dns.RcodeToString[ra.Rcode])
	}
	if dnsType == dns.TypeA && ra.Answer[0].(*dns.A).A.String() != content {
		return fmt.Errorf("Invalid content '%s'. Expected '%s'", ra.Answer[0].(*dns.A).A.String(), content)
	}
	if dnsType == dns.TypeAAAA && ra.Answer[0].(*dns.AAAA).AAAA.String() != content {
		return fmt.Errorf("Invalid content '%s'. Expected '%s'", ra.Answer[0].(*dns.AAAA).AAAA.String(), content)
	}

	return nil
}
