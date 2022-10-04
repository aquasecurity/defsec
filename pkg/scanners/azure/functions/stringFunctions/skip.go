package stringFunctions

func Skip(args ...interface{}) interface{} {
	if len(args) != 2 {
		return ""
	}

	input, ok := args[0].(string)
	if !ok {
		return ""
	}

	count, ok := args[1].(int)
	if !ok {
		return ""
	}

	if count > len(input) {
		return ""
	}

	return input[count:]
}
