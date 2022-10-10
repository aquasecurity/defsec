package functions

var counter int

func CopyIndex(args ...interface{}) interface{} {

	if len(args) != 0 {
		return nil
	}
	// this is a very blunt implementation of copyIndex as it
	// does not know which resource is being counted so just gives an incrementing
	// number for each call
	counter++
	return counter
}
