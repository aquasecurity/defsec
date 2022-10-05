package stringFunctions

func Take(args ...interface{}) interface{} {
	if len(args) != 2 {
		return ""
	}

	count, ok := args[1].(int)
	if !ok {
		return ""
	}

	switch input := args[0].(type) {
	case string:
		if count > len(input) {
			return input
		}
		return input[:count]
	case []string:
		if count > len(input) {
			return input
		}
		return input[:count]
	}

	return ""
}
