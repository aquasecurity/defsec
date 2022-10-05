package functions

import "time"

func UTCNow(args ...interface{}) interface{} {
	if len(args) > 1 {
		return nil
	}

	if len(args) == 1 {
		format, ok := args[0].(string)
		if ok {
			return time.Now().UTC().Format(format)
		}
	}

	return time.Now().UTC().Format(time.RFC3339)
}
