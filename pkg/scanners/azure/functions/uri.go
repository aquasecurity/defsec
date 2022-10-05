package functions

import "net/url"

func Uri(args ...interface{}) interface{} {
	if len(args) != 2 {
		return ""
	}

	path, err := url.JoinPath(args[0].(string), args[1].(string))
	if err != nil {
		return ""
	}
	return path
}
