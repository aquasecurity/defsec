package debug

import (
	"fmt"
)

var errors []string

// Error ...
func Error(format string, args ...interface{}) {
	if !Enabled {
		return
	}
	errors = append(errors, fmt.Sprintf(format, args...))

}
