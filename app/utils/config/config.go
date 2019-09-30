package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/file"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
)

// App
var (
	AppName    = "WindowsSpyBlocker"
	AppVersion = "0.0.0"
	AppURL     = "https://github.com/crazy-max/WindowsSpyBlocker"
)

// Config
var (
	App      conf
	Settings settings
)

// Lib structure
type Lib struct {
	Url        string `json:"url"`
	Dest       string
	OutputPath string
	Checkfile  string `json:"checkfile"`
}

// NcsiProbe structure
type NcsiProbe struct {
	WebHostV4    string `json:"webHostV4"`
	WebPathV4    string `json:"webPathV4"`
	WebContentV4 string `json:"webContentV4"`
	WebHostV6    string `json:"webHostV6"`
	WebPathV6    string `json:"webPathV6"`
	WebContentV6 string `json:"webContentV6"`
	DnsHostV4    string `json:"dnsHostV4"`
	DnsContentV4 string `json:"dnsContentV4"`
	DnsHostV6    string `json:"dnsHostV6"`
	DnsContentV6 string `json:"dnsContentV6"`
}

type dataTpl struct {
	Head  string `json:"head"`
	Value string `json:"value"`
}

type conf struct {
	Version         string `json:"version"`
	Debug           bool   `json:"debug"`
	UseEmbeddedData bool   `json:"useEmbeddedData"`
	Proxifier       struct {
		LogPath string `json:"logPath"`
	} `json:"proxifier"`
	Sysmon struct {
		EvtxPath string `json:"evtxPath"`
	} `json:"sysmon"`
	Wireshark struct {
		PcapngPath string `json:"pcapngPath"`
		Capture    struct {
			Interface int    `json:"interface"`
			Filter    string `json:"filter"`
		} `json:"capture"`
	} `json:"wireshark"`
	Exclude struct {
		Ips   []string `json:"ips"`
		Hosts []string `json:"hosts"`
		Orgs  []string `json:"orgs"`
	} `json:"exclude"`
}

type settings struct {
	Uris struct {
		LatestVersion string `json:"latestVersion"`
		Threatcrowd   string `json:"threatcrowd"`
		Whatis        string `json:"whatis"`
		Dnsquery      string `json:"dnsquery"`
		Ipapi         string `json:"ipapi"`
		Ipinfo        string `json:"ipinfo"`
		Ipnf          string `json:"ipnf"`
		Ip6           string `json:"ip6"`
	} `json:"uris"`
	Libs struct {
		Wireshark32 Lib `json:"wireshark_32"`
		Wireshark64 Lib `json:"wireshark_64"`
		Npcap       Lib `json:"npcap"`
		Sysmon      Lib `json:"sysmon"`
	} `json:"libs"`
	DataTpl struct {
		Dnscrypt dataTpl `json:"dnscrypt"`
		Openwrt  struct {
			Ip      dataTpl `json:"ip"`
			Domains dataTpl `json:"domains"`
		} `json:"openwrt"`
		P2p       dataTpl `json:"p2p"`
		Proxifier struct {
			Ip      dataTpl `json:"ip"`
			Domains dataTpl `json:"domains"`
		} `json:"proxifier"`
		Simplewall dataTpl `json:"simplewall"`
	} `json:"dataTpl"`
	Proxifier struct {
		UnvalidLines []string `json:"unvalidLines"`
	} `json:"proxifier"`
	Sysmon struct {
		EvtxPath string `json:"evtxPath"`
	} `json:"sysmon"`
	Ncsi struct {
		Reg struct {
			Key               string `json:"key"`
			WebProbeHost      string `json:"webProbeHost"`
			WebProbePath      string `json:"webProbePath"`
			WebProbeContent   string `json:"webProbeContent"`
			WebProbeHostV6    string `json:"webProbeHostV6"`
			WebProbePathV6    string `json:"webProbePathV6"`
			WebProbeContentV6 string `json:"webProbeContentV6"`
			DnsProbeHost      string `json:"dnsProbeHost"`
			DnsProbeContent   string `json:"dnsProbeContent"`
			DnsProbeHostV6    string `json:"dnsProbeHostV6"`
			DnsProbeContentV6 string `json:"dnsProbeContentV6"`
		} `json:"reg"`
		Probes struct {
			Microsoft NcsiProbe `json:"microsoft"`
			Wsb       NcsiProbe `json:"wsb"`
		} `json:"probes"`
	} `json:"ncsi"`
	WilcardSubdomains []string `json:"wilcardSubdomains"`
}

func init() {
	var err error
	var old conf

	cfgPath := path.Join(pathu.Current, "app.conf")

	// Load default config
	defaultConf, err := bindata.Asset("app.conf")
	if err != nil {
		err = fmt.Errorf("Cannot load asset app.conf: %s", err.Error())
		print.QuitFatal(err)
	}
	err = json.Unmarshal(defaultConf, &App)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall defaultConf: %s", err.Error())
		print.QuitFatal(err)
	}
	newVersion := App.Version

	// Create conf if not exists
	if _, err := os.Stat(cfgPath); err != nil {
		err = ioutil.WriteFile(cfgPath, defaultConf, 0644)
		if err != nil {
			err = fmt.Errorf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
			print.QuitFatal(err)
		}
	}

	// Load current config
	raw, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		err = fmt.Errorf("Cannot read %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		print.QuitFatal(err)
	}
	err = json.Unmarshal(raw, &old)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		print.QuitFatal(err)
	}

	// Perform upgrade if different version
	if newVersion != old.Version {
		if err := performUpgrade(); err != nil {
			print.QuitFatal(err)
		}
	}

	// Merge config
	err = json.Unmarshal(raw, &App)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		print.QuitFatal(err)
	}
	App.Version = newVersion

	// Write config
	cfgJson, _ := json.MarshalIndent(App, "", "  ")
	if err != nil {
		err = fmt.Errorf("Cannot marshal config: %s", err.Error())
		print.QuitFatal(err)
	}
	err = ioutil.WriteFile(cfgPath, cfgJson, 0644)
	if err != nil {
		err = fmt.Errorf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		print.QuitFatal(err)
	}

	// Load settings
	rawSettings, err := bindata.Asset("app/settings.json")
	if err != nil {
		err = fmt.Errorf("Cannot load asset settings.json: %s", err.Error())
		print.QuitFatal(err)
	}
	err = json.Unmarshal(rawSettings, &Settings)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall settings: %s", err.Error())
		print.QuitFatal(err)
	}
}

func performUpgrade() error {
	// Remove content of libs folder
	if err := file.RemoveContents(pathu.Libs); err != nil {
		return err
	}

	return nil
}
