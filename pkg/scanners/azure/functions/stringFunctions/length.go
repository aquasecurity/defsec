package stringFunctions

func Length(args ...interface{}) interface{} {

	if len(args) != 1 {
		return 0
	}

	input, ok := args[0].(string)
	if !ok {
		return 0
	}
	return len(input)

}
