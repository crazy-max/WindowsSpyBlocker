package dev

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"time"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/config"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/data"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/netu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/stringsu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/timeu"
	"github.com/fatih/color"
)

func merge(args ...string) (err error) {
	mergeFirewall(data.RULES_EXTRA)
	mergeFirewall(data.RULES_SPY)
	mergeFirewall(data.RULES_UPDATE)
	mergeHosts(data.RULES_EXTRA)
	mergeHosts(data.RULES_SPY)
	mergeHosts(data.RULES_UPDATE)
	return nil
}

func mergeFirewall(rule string) {
	fmt.Println()
	color.New(color.FgHiYellow, color.Bold).Printf("Firewall %s", rule)
	fmt.Println()
	firewallDataPath := path.Join(pathu.Current, "data", data.TYPE_FIREWALL, rule+".txt")

	fmt.Printf("Seeking %s... ", strings.TrimLeft(firewallDataPath, pathu.Current))
	if _, err := os.Stat(firewallDataPath); err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	fmt.Printf("Opening %s... ", strings.TrimLeft(firewallDataPath, pathu.Current))
	logFile, err := os.Open(firewallDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	defer logFile.Close()

	fmt.Printf("Reading %s... ", strings.TrimLeft(firewallDataPath, pathu.Current))
	firewallDataBuf, err := ioutil.ReadFile(firewallDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	//print.Pretty(strings.Split(string(firewallDataBuf), "\n"))

	err = mergeExtIPs(rule, data.EXT_OPENWRT, firewallDataBuf)
	if err != nil {
		return
	}

	err = mergeExtIPs(rule, data.EXT_P2P, firewallDataBuf)
	if err != nil {
		return
	}

	err = mergeExtIPs(rule, data.EXT_PROXIFIER, firewallDataBuf)
	if err != nil {
		return
	}

	err = mergeExtIPs(rule, data.EXT_SIMPLEWALL, firewallDataBuf)
	if err != nil {
		return
	}
}

func mergeHosts(rule string) {
	fmt.Println()
	color.New(color.FgHiYellow, color.Bold).Printf("Hosts %s", rule)
	fmt.Println()
	hostsDataPath := path.Join(pathu.Current, "data", data.TYPE_HOSTS, rule+".txt")

	fmt.Printf("Seeking %s... ", strings.TrimLeft(hostsDataPath, pathu.Current))
	if _, err := os.Stat(hostsDataPath); err != nil {
		print.Error(err)
		return
	}
	print.Ok()

	fmt.Printf("Opening %s... ", strings.TrimLeft(hostsDataPath, pathu.Current))
	logFile, err := os.Open(hostsDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	defer logFile.Close()

	fmt.Printf("Reading %s... ", strings.TrimLeft(hostsDataPath, pathu.Current))
	hostsDataBuf, err := ioutil.ReadFile(hostsDataPath)
	if err != nil {
		print.Error(err)
		return
	}
	print.Ok()
	//print.Pretty(strings.Split(string(firewallDataBuf), "\n"))

	err = mergeExtHosts(rule, data.EXT_DNSCRYPT, hostsDataBuf)
	if err != nil {
		return
	}

	err = mergeExtHosts(rule, data.EXT_OPENWRT, hostsDataBuf)
	if err != nil {
		return
	}

	err = mergeExtHosts(rule, data.EXT_PROXIFIER, hostsDataBuf)
	if err != nil {
		return
	}
}

func mergeExtIPs(rule string, ext string, firewallDataBuf []byte) error {
	asCidr := false
	outputPath := ""
	fileHead := ""
	fileIpValue := ""

	if ext == data.EXT_OPENWRT {
		asCidr = true
		outputPath = path.Join(pathu.Data, ext, rule, "firewall.user")
		fileHead = fmt.Sprintf(string(config.Settings.DataTpl.Openwrt.Ip.Head), rule, config.AppURL)
		fileIpValue = string(config.Settings.DataTpl.Openwrt.Ip.Value)
	} else if ext == data.EXT_P2P {
		asCidr = false
		outputPath = path.Join(pathu.Data, ext, rule+".txt")
		fileHead = fmt.Sprintf(string(config.Settings.DataTpl.P2p.Head), rule, config.AppURL)
		fileIpValue = string(config.Settings.DataTpl.P2p.Value)
	} else if ext == data.EXT_PROXIFIER {
		asCidr = false
		outputPath = path.Join(pathu.Data, ext, rule, "ips.txt")
		fileHead = string(config.Settings.DataTpl.Proxifier.Ip.Head)
		fileIpValue = string(config.Settings.DataTpl.Proxifier.Ip.Value)
	} else if ext == data.EXT_SIMPLEWALL {
		asCidr = false
		outputPath = path.Join(pathu.Data, ext, rule, "blocklist.xml")
		fileHead = fmt.Sprintf(string(config.Settings.DataTpl.Simplewall.Head), rule, config.AppURL, timeu.CurrentTime.Format(time.RFC1123Z))
		fileIpValue = string(config.Settings.DataTpl.Simplewall.Value)
	}

	color.New(color.FgMagenta).Printf("\nProcessing %s\n", ext)

	fmt.Printf("Getting %s data... ", ext)
	extData, err := data.GetExtIPs(ext, rule)
	if err != nil {
		print.Error(err)
		return err
	}
	print.Ok()

	fmt.Printf("Seeking diffs for %s... ", ext)
	result, added, removed, err := getMergeDiffsIPs(data.GetIPsSlice(extData), firewallDataBuf, asCidr)
	if err != nil {
		print.Error(err)
		return err
	} else if len(added) == 0 && len(removed) == 0 {
		color.New(color.FgYellow).Print("0 diff found\n")
	} else {
		if len(added) > 0 {
			color.New(color.FgGreen).Printf("%d added", len(added))
		}
		if len(added) > 0 && len(removed) > 0 {
			fmt.Print(" ; ")
		}
		if len(removed) > 0 {
			color.New(color.FgRed).Printf("%d removed", len(removed))
		}
		fmt.Print("\n")
	}

	if _, err := os.Stat(path.Dir(outputPath)); os.IsNotExist(err) {
		fmt.Printf("Creating folder %s... ", strings.TrimLeft(path.Dir(outputPath), pathu.Current))
		if err := file.CreateSubfolder(path.Dir(outputPath)); err != nil {
			print.Error(err)
			return err
		}
		print.Ok()
	}

	fmt.Printf("Generating %s... ", strings.TrimLeft(outputPath, pathu.Current))
	outputFile, _ := os.Create(outputPath)
	outputFile.WriteString(fileHead)
	count := 0
	for _, ip := range result {
		if count > 0 {
			outputFile.WriteString("\n")
		}
		if ext == data.EXT_P2P && !strings.Contains(ip.IP, "-") {
			outputFile.WriteString(fmt.Sprintf(fileIpValue, ip.IP+"-"+ip.IP))
		} else if ext == data.EXT_SIMPLEWALL {
			outputFile.WriteString(fmt.Sprintf(fileIpValue, rule, ip.IP, ip.IP))
		} else {
			outputFile.WriteString(fmt.Sprintf(fileIpValue, ip.IP))
		}
		count++
	}
	if ext == data.EXT_SIMPLEWALL {
		outputFile.WriteString("\n</root>")
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(outputPath, pathu.Current))
	if err := outputFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	outputFile.Close()

	return nil
}

func mergeExtHosts(rule string, ext string, hostsDataBuf []byte) error {
	outputPath := ""
	fileHead := ""
	fileValue := ""
	asWildcard := false
	if ext == data.EXT_DNSCRYPT {
		outputPath = path.Join(pathu.Data, ext, rule+".txt")
		fileHead = string(config.Settings.DataTpl.Dnscrypt.Head)
		fileValue = string(config.Settings.DataTpl.Dnscrypt.Value)
		asWildcard = true
	} else if ext == data.EXT_OPENWRT {
		outputPath = path.Join(pathu.Data, ext, rule, "dnsmasq.conf")
		fileHead = fmt.Sprintf(string(config.Settings.DataTpl.Openwrt.Domains.Head), rule, config.AppURL)
		fileValue = string(config.Settings.DataTpl.Openwrt.Domains.Value)
		asWildcard = false
	} else if ext == data.EXT_PROXIFIER {
		outputPath = path.Join(pathu.Data, ext, rule, "domains.txt")
		fileHead = string(config.Settings.DataTpl.Proxifier.Domains.Head)
		fileValue = string(config.Settings.DataTpl.Proxifier.Domains.Value)
		asWildcard = true
	}

	color.New(color.FgMagenta).Printf("\nProcessing %s\n", ext)

	fmt.Printf("Getting %s data... ", ext)
	extData, err := data.GetExtHosts(ext, rule)
	if err != nil {
		print.Error(err)
		return err
	}
	print.Ok()

	fmt.Printf("Seeking diffs for %s... ", ext)
	result, added, removed, err := getMergeDiffsHosts(data.GetHostsSlice(extData), hostsDataBuf, asWildcard)
	if err != nil {
		print.Error(err)
		return err
	} else if len(added) == 0 && len(removed) == 0 {
		color.New(color.FgYellow).Print("0 diff found\n")
	} else {
		if len(added) > 0 {
			color.New(color.FgGreen).Printf("%d added", len(added))
		}
		if len(added) > 0 && len(removed) > 0 {
			fmt.Print(" ; ")
		}
		if len(removed) > 0 {
			color.New(color.FgRed).Printf("%d removed", len(removed))
		}
		fmt.Print("\n")
	}

	if _, err := os.Stat(path.Dir(outputPath)); os.IsNotExist(err) {
		fmt.Printf("Creating folder %s... ", strings.TrimLeft(path.Dir(outputPath), pathu.Current))
		if err := file.CreateSubfolder(path.Dir(outputPath)); err != nil {
			print.Error(err)
			return err
		}
		print.Ok()
	}

	fmt.Printf("Generating %s... ", strings.TrimLeft(outputPath, pathu.Current))
	outputFile, _ := os.Create(outputPath)
	outputFile.WriteString(fileHead)
	count := 0
	for _, domain := range result {
		if count > 0 {
			outputFile.WriteString("\n")
		}
		outputFile.WriteString(fmt.Sprintf(fileValue, domain.Domain))
		count++
	}
	print.Ok()

	fmt.Printf("Writing %s... ", strings.TrimLeft(outputPath, pathu.Current))
	if err := outputFile.Sync(); err != nil {
		print.Error(err)
	} else {
		print.Ok()
	}
	outputFile.Close()

	return nil
}

func getMergeDiffsIPs(extIps []string, firewallIPsBuf []byte, asCidr bool) (ips, []string, []string, error) {
	var result ips
	var added []string
	var removed []string
	var err error

	var firewallIP string
	var firewallIPs []string

	newBuf := bytes.NewBuffer(firewallIPsBuf)
	for {
		firewallIP, err = newBuf.ReadString('\n')
		if len(firewallIP) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				}
				return result, nil, nil, err
			}
		}
		firewallIP = strings.TrimSpace(firewallIP)
		if strings.HasPrefix(firewallIP, "#") || firewallIP == "" {
			continue
		}
		firewallIPs = append(firewallIPs, firewallIP)
		if asCidr && strings.Contains(firewallIP, "-") {
			firewallIP, err = netu.GetCIDRFromIPRange(firewallIP)
			if err != nil {
				return result, nil, nil, err
			}
		} else if !asCidr && strings.Contains(firewallIP, "/") {
			firewallIP, err = netu.GetIPRangeFromCIDR(firewallIP)
			if err != nil {
				return result, nil, nil, err
			}
		}
		if !stringsu.InSlice(firewallIP, extIps) {
			added = append(added, firewallIP)
		}
		result = append(result, ip{IP: firewallIP})
	}

	for _, extIp := range extIps {
		if strings.Contains(extIp, "/") {
			extIp, err = netu.GetIPRangeFromCIDR(extIp)
			if err != nil {
				return result, nil, nil, err
			}
		}
		if !stringsu.InSlice(extIp, firewallIPs) {
			removed = append(removed, extIp)
		}
	}

	sort.Sort(result)
	return result, added, removed, nil
}

func getMergeDiffsHosts(extHosts []string, hostsBuf []byte, asWildcard bool) (hosts, []string, []string, error) {
	var result hosts
	var added []string
	var removed []string
	var err error

	var domain string
	var domains []string

	newBuf := bytes.NewBuffer(hostsBuf)
	for {
		domain, err = newBuf.ReadString('\n')
		if len(domain) == 0 {
			if err != nil {
				if err == io.EOF {
					break
				}
				return result, nil, nil, err
			}
		}
		domain = strings.TrimRight(strings.Replace(strings.TrimSpace(domain), "0.0.0.0 ", "", 1), ":443")
		if strings.HasPrefix(domain, "#") || domain == "" {
			continue
		}
		if asWildcard {
			for _, wildcard := range config.Settings.WilcardSubdomains {
				exp := strings.Replace(strings.Replace(wildcard, "*", `([^"]+)`, -1), ".", `\.`, -1)
				re := regexp.MustCompile(`(?i)` + exp)
				if re.MatchString(domain) {
					domain = wildcard
					break
				}
			}
		}
		if !stringsu.InSlice(domain, domains) {
			domains = append(domains, domain)
		} else {
			continue
		}
		if !stringsu.InSlice(domain, extHosts) {
			added = append(added, domain)
		}
		result = append(result, host{Domain: domain})
	}

	for _, extHost := range extHosts {
		if !stringsu.InSlice(extHost, domains) {
			removed = append(removed, extHost)
		}
	}

	sort.Sort(result)
	return result, added, removed, nil
}
