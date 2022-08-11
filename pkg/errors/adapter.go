package errors

import "strings"

type AdapterError struct {
	Errors       []error
	errorStrings []string
}

func NewAdapterError(errs []error) AdapterError {

	var errorStrings []string
	for _, err := range errs {
		errorStrings = append(errorStrings, err.Error())
	}

	return AdapterError{
		Errors:       errs,
		errorStrings: errorStrings,
	}
}

func (e AdapterError) Error() string {
	return strings.Join(e.errorStrings, "\n")
}
