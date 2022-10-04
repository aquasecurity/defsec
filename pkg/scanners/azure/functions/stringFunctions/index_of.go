package stringFunctions

import "strings"

func IndexOf(args ...interface{}) interface{} {

	if len(args) != 2 {
		return -1
	}

	stringToSearch, ok := args[0].(string)
	if !ok {
		return -1
	}

	stringToFind, ok := args[1].(string)
	if !ok {
		return -1
	}

	return strings.Index(stringToSearch, stringToFind)
}
