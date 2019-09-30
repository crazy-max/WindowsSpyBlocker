// +build mage

package main

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Default mage target
var Default = Build

var (
	chocoPath      = path.Join("chocolatey")
	binPath        = path.Join("bin")
	chocoBinPath   = path.Join("bin", "choco")
	chocoLegalPath = path.Join(chocoBinPath, "legal")
	chocoToolsPath = path.Join(chocoBinPath, "tools")
	chocoNuspec    = path.Join(chocoBinPath, "windowsspyblocker.nuspec")
	wsbPath        = path.Join(binPath, "WindowsSpyBlocker.exe")
	wsbEnv         = map[string]string{
		"GO111MODULE": "on",
		"GOPROXY":     "https://goproxy.io",
		"GOOS":        "windows",
		"GOARCH":      "386",
		"CGO_ENABLED": "0",
	}
)

// Build Run go build
func Build() error {
	mg.Deps(Clean)
	mg.Deps(Generate)

	var args []string
	args = append(args, "build", "-o", wsbPath, "-v")
	args = append(args, "-ldflags", flags())

	fmt.Println("⚙️ Go build...")
	if err := sh.RunWith(wsbEnv, mg.GoCmd(), args...); err != nil {
		return err
	}

	return nil
}

// Clean Remove files generated at build-time
func Clean() error {
	if err := createDir(binPath); err != nil {
		return err
	}
	if err := cleanDir(binPath); err != nil {
		return err
	}
	return nil
}

// Download Run go mod download
func Download() error {

	fmt.Println("⚙️ Go mod download...")
	if err := sh.RunWith(wsbEnv, mg.GoCmd(), "mod", "download"); err != nil {
		return err
	}

	return nil
}

// Generate Run go generate
func Generate() error {
	mg.Deps(Download)
	mg.Deps(appConf)
	mg.Deps(manifest)
	mg.Deps(versionInfo)

	fmt.Println("⚙️ Go generate...")
	if err := sh.RunV(mg.GoCmd(), "generate", "-v"); err != nil {
		return err
	}

	return nil
}

// ChocoPack Run choco pack
func ChocoPack() error {
	mg.Deps(ChocoPrepare)

	fmt.Println("⚙️ Chocolatey package...")
	choco, err := exec.LookPath("choco")
	if err != nil {
		return err
	}

	var args []string
	args = append(args, "pack", "--out", binPath)
	args = append(args, "--version", tag())
	args = append(args, "--acceptlicense", "--yes")
	args = append(args, chocoNuspec)

	if err := sh.RunV(choco, args...); err != nil {
		return err
	}

	return nil
}

// ChocoPrepare Generate chocolatey files
func ChocoPrepare() error {
	fmt.Println("🔨 Generating Chocolatey files...")

	if err := createDir(chocoBinPath); err != nil {
		return err
	}
	if err := cleanDir(chocoBinPath); err != nil {
		return err
	}
	if err := copyDir(chocoPath, chocoBinPath); err != nil {
		return err
	}
	if err := createDir(chocoLegalPath); err != nil {
		return err
	}
	if err := copyFile("LICENSE", path.Join(chocoLegalPath, "LICENSE.txt")); err != nil {
		return err
	}
	if err := copyFile(wsbPath, path.Join(chocoToolsPath, "WindowsSpyBlocker.exe")); err != nil {
		return err
	}

	nuspec, err := ioutil.ReadFile(chocoNuspec)
	if err != nil {
		return err
	}
	nuspecContent := strings.Replace(string(nuspec), "<version>0.0.0</version>", fmt.Sprintf("<version>%s</version>", tag()), -1)
	err = ioutil.WriteFile(chocoNuspec, []byte(nuspecContent), 0)
	if err != nil {
		return err
	}

	return nil
}

// flags returns ldflags
func flags() string {
	//hash := hash()
	mod := mod()
	tag := tag()
	return fmt.Sprintf(`-s -w -X "%s/app/utils/config.AppVersion=%s"`, mod, tag)
}

// mod returns module name
func mod() string {
	f, err := os.Open("go.mod")
	if err == nil {
		reader := bufio.NewReader(f)
		line, _, _ := reader.ReadLine()
		return strings.Replace(string(line), "module ", "", 1)
	}
	return ""
}

// tag returns the git tag for the current branch or "" if none.
func tag() string {
	s, _ := sh.Output("bash", "-c", "git describe --abbrev=0 --tags 2> /dev/null")
	if s == "" {
		return "0.0.0"
	}
	return s
}

// hash returns the git hash for the current repo or "" if none.
func hash() string {
	hash, _ := sh.Output("git", "rev-parse", "--short", "HEAD")
	return hash
}

// appConf generates app.conf file
func appConf() error {
	fmt.Println("🔨 Generating app.conf...")

	var tpl = template.Must(template.New("").Parse(`{
  "version": "{{ .Version }}",
  "debug": false,
  "useEmbeddedData": true,
  "proxifier": {
    "logPath": "C:/Users/[username]/Documents/Proxifier/Log.txt"
  },
  "sysmon": {
    "evtxPath": "C:/WINDOWS/system32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx"
  },
  "wireshark": {
    "pcapngPath": "C:/Users/[username]/Documents/Wireshark/cap.pcapng",
    "capture": {
      "interface": 1,
      "filter": "not arp and port not 53 and not icmp and not icmp6 and not broadcast"
    }
  },
  "exclude": {
    "ips": [
      "0.0.0.0",
      "127.0.0.1",
      "192.168.0.0-192.168.0.255",
      "8.8.8.8",
      "8.8.4.4",
      "255.255.255.255"
    ],
    "hosts": [
      "MyComputer",
      "localhost",
      "localhost.localdomain",
      "*.local",
      "yourISP.com",
      "*.yourISP.com",
      "wireshark.org",
      "*.wireshark.org"
    ],
    "orgs": [
      "*facebook*"
    ]
  }
}
`))

	f, err := os.Create("app.conf")
	if err != nil {
		return err
	}
	defer f.Close()

	return tpl.Execute(f, struct {
		Version string
	}{
		Version: tag(),
	})
}

// manifest generates manifest for versioninfo
func manifest() error {
	fmt.Println("🔨 Generating app.manifest...")

	file, err := os.Create("app.manifest")
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.WriteString(file, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
        <security>
            <requestedPrivileges>
            <requestedExecutionLevel level="requireAdministrator"
                uiAccess="false" />
        </requestedPrivileges>
    </security>
    </trustInfo>
</assembly>`)
	if err != nil {
		return err
	}

	return nil
}

// versionInfo generates versioninfo.json
func versionInfo() error {
	fmt.Println("🔨 Generating versioninfo.json...")

	var tpl = template.Must(template.New("").Parse(`{
	"FixedFileInfo":
	{
		"FileFlagsMask": "3f",
		"FileFlags ": "00",
		"FileOS": "040004",
		"FileType": "01",
		"FileSubType": "00"
	},
	"StringFileInfo":
	{
		"Comments": "",
		"CompanyName": "",
		"FileDescription": "Block spying and tracking on Windows",
		"FileVersion": "{{ .Version }}.0",
		"InternalName": "",
		"LegalCopyright": "https://{{ .Package }}",
		"LegalTrademarks": "",
		"OriginalFilename": "WindowsSpyBlocker.exe",
		"PrivateBuild": "",
		"ProductName": "WindowsSpyBlocker",
		"ProductVersion": "{{ .Version }}.0",
		"SpecialBuild": ""
	},
	"VarFileInfo":
	{
		"Translation": {
			"LangID": "0409",
			"CharsetID": "04B0"
		}
	}
}`))

	f, err := os.Create("versioninfo.json")
	if err != nil {
		return err
	}
	defer f.Close()

	return tpl.Execute(f, struct {
		Package string
		Version string
	}{
		Package: mod(),
		Version: tag(),
	})
}

func createDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 777)
	}
	return nil
}

func cleanDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func copyDir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}

	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = copyDir(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		} else {
			if err = copyFile(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		}
	}

	return nil
}

func copyFile(src string, dest string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return err
	}

	err = destFile.Sync()
	if err != nil {
		return err
	}

	return nil
}
