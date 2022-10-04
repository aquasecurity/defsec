package stringFunctions

import (
	"fmt"
)

func Concat(args ...interface{}) interface{} {
	var result string

	for _, arg := range args {
		result += fmt.Sprintf("%v", arg)
	}

	return result
}
