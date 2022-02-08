package debug

import (
	"fmt"
	"time"
)

// Enabled ...
var Enabled bool

// Log ...
func Log(format string, args ...interface{}) {
	if !Enabled {
		return
	}
	line := fmt.Sprintf(format, args...)
	fmt.Printf("[DEBUG][%s] %s\n", time.Now(), line)
}
