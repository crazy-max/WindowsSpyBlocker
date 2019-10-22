// Package menu fork of https://github.com/turret-io/go-menu
package menu

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
	"github.com/akyoto/color"
)

// CommandOption main struct to handle options for Description, and the function that should be called
type CommandOption struct {
	Description string
	Color       color.Attribute
	Function    func(args ...string) error
}

// Options sets name, prompt, character width of menu, and command
// used to display the menu
type Options struct {
	Name        string
	Prompt      string
	MenuLength  int
	MenuCommand string
}

// Menu struct encapsulates Commands and Options
type Menu struct {
	Commands []CommandOption
	Options  Options
}

// NewOptions to setup the options for the menu.
// An empty string for prompt and a length of 0 will use the
// default "> " prompt and 100 character wide menu. An empty
// string for menuCommand will use the default 'menu' command.
func NewOptions(name string, prompt string, length int, menuCommand string) Options {
	return Options{name, prompt, length, menuCommand}
}

// Trim whitespace, newlines, and create command+arguments slice
func cleanCommand(cmd string) ([]string, error) {
	cmdArgs := strings.Split(strings.Trim(cmd, " \r\n"), " ")
	return cmdArgs, nil
}

// NewMenu creates a new menu with options
func NewMenu(cmds []CommandOption, options Options) *Menu {
	if options.Prompt == "" {
		options.Prompt = "> "
	}
	if options.MenuLength == 0 {
		options.MenuLength = 100
	}
	if options.MenuCommand == "" {
		options.MenuCommand = "menu"
	}
	return &Menu{
		Commands: cmds,
		Options:  options,
	}
}

func (m *Menu) prompt() {
	fmt.Print(m.Options.Prompt)
}

// Write menu from CommandOptions
func (m *Menu) menu() {
	// Menu name
	fmt.Println()
	color.New(color.FgHiCyan, color.Bold).Print("# ", m.Options.Name, "\n")

	idCmd := 1
	for i := range m.Commands {
		// Command ID
		color.New(color.Bold).Printf(" %d", idCmd)
		fmt.Print(" - ")

		// Command Description
		color.New(m.Commands[i].Color).Printf("%s", m.Commands[i].Description)
		fmt.Println()

		idCmd += 1
	}

	fmt.Println()
	color.New(color.FgMagenta).Println("* Type 'back' to go to the previous menu")
	color.New(color.FgMagenta).Println("* Type 'exit' to leave WindowsSpyBlocker")
	fmt.Println()
}

// Start is a wrapper for providing Stdin to the main menu loop
func (m *Menu) Start() {
	m.start(os.Stdin)
}

// Main loop
func (m *Menu) start(reader io.Reader) {
	m.menu()

Loop:
	for {
		input := bufio.NewReader(reader)
		// Prompt for input
		m.prompt()

		inputString, err := input.ReadString('\n')
		if err != nil {
			// If we didn't receive anything from ReadString
			// we shouldn't continue because we're not blocking
			// anymore but we also don't have any data
			break Loop
		}

		cmd, _ := cleanCommand(inputString)
		if len(cmd) < 1 {
			break Loop
		}

		// Route the first index of the cmd slice to the appropriate case
	Route:
		switch cmd[0] {
		case "exit":
			os.Exit(0)
		case "back":
			break Loop
		case m.Options.MenuCommand:
			m.menu()
			break
		default:
			if currentIdCmd, err := strconv.Atoi(cmd[0]); err == nil {
				idCmd := 1
				for i := range m.Commands {
					if idCmd == currentIdCmd {
						err := m.Commands[i].Function(cmd[1:]...)
						fmt.Println()
						if err != nil {
							print.QuitFatal(err)
						}
						break Route
					}
					idCmd += 1
				}
			}
			if cmd[0] != "" {
				print.ErrorStr(fmt.Sprintf("Unknown command '%s'\n", cmd[0]))
			}
		}
	}
}
