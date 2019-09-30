// +build tools

package tools

import (
	// Import goversioninfo tool
	_ "github.com/josephspurrier/goversioninfo/cmd/goversioninfo"
	// Import go-bindata tool
	_ "github.com/kevinburke/go-bindata/go-bindata"
	// Import mage tool
	_ "github.com/magefile/mage"
)
