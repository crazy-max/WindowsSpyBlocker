package print

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/akyoto/color"
)

// Error printed in red color
func Error(err error) {
	color.New(color.FgRed).Printf("Error: %s\n", err.Error())
}

// ErrorStr printed in red color
func ErrorStr(str string) {
	color.New(color.FgRed).Printf("Error: %s\n", str)
}

// Ok printed in green color
func Ok() {
	color.New(color.FgGreen).Print("OK!\n")
}

// RegString printed in color
func RegString(name string, value string) {
	color.New(color.FgYellow).Printf("%s", name)
	fmt.Print(" = ")
	color.New(color.FgCyan).Printf("%s\n", value)
}

// Pretty print of struct or slice
func Pretty(v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// QuitFatal quit the app and wait for user input
func QuitFatal(err error) {
	color.New(color.FgHiRed, color.Bold).Printf("\nFatal: %s\n", err.Error())
	fmt.Print("Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')
	os.Exit(1)
}
