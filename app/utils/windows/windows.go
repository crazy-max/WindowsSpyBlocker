package windows

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/akyoto/color"
	"golang.org/x/sys/windows/registry"
)

// OpenRegKey opens a registry key
func OpenRegKey(key registry.Key, path string, access uint32) (registry.Key, error) {
	fmt.Print("Opening key ")
	color.New(color.FgYellow).Printf("%s", path)
	fmt.Print("...")

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, access)
	if err != nil {
		print.Error(err)
		return key, err
	}

	print.Ok()
	return key, nil
}

// GetRegString gets a string value of a registry key
func GetRegString(key registry.Key, name string) string {
	fmt.Print("Getting reg value of ")
	color.New(color.FgYellow).Printf("%s", name)
	fmt.Print("...")

	value, _, err := key.GetStringValue(name)
	if err != nil {
		print.Error(err)
		return ""
	}

	print.Ok()
	return value
}

// SetRegString sets a string value of a registry key
func SetRegString(key registry.Key, name string, value string) error {
	fmt.Print("Setting ")
	color.New(color.FgYellow).Printf("%s", name)
	fmt.Print(" to ")
	color.New(color.FgCyan).Printf("'%s'", value)
	fmt.Print("...")

	if err := key.SetStringValue(name, value); err != nil {
		print.Error(err)
		return err
	}

	print.Ok()
	return nil
}

// SetConsoleTitle sets windows console title
func SetConsoleTitle(title string) (int, error) {
	handle, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		print.Error(err)
		return 0, err
	}
	defer syscall.FreeLibrary(handle)

	proc, err := syscall.GetProcAddress(handle, "SetConsoleTitleW")
	if err != nil {
		print.Error(err)
		return 0, err
	}

	rTitle, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		print.Error(err)
		return 0, err
	}

	r, _, err := syscall.Syscall(proc, 1, uintptr(unsafe.Pointer(rTitle)), 0, 0)
	return int(r), err
}

// Is64Arch detects if program running on 64bits architecture
func Is64Arch() bool {
	return strings.ContainsAny("64", os.Getenv("PROCESSOR_ARCHITECTURE"))
}
