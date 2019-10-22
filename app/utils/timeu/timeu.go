package timeu

import (
	"fmt"
	"time"

	"github.com/akyoto/color"
	"github.com/hako/durafmt"
)

var CurrentTime = time.Now().Local()

// Track execution time
func Track(start time.Time) {
	fmt.Print("\nTime spent: ")
	color.New(color.FgMagenta).Printf("%s\n", durafmt.Parse(time.Since(start)))
}
