package errs

import "strings"

type AdapterError struct {
	errs         []error
	errorStrings []string
}

func NewAdapterError(errs []error) AdapterError {

	var errorStrings []string
	for _, err := range errs {
		errorStrings = append(errorStrings, err.Error())
	}

	return AdapterError{
		errs:         errs,
		errorStrings: errorStrings,
	}
}

func (e *AdapterError) Errors() []error {
	return e.errs
}

func (e AdapterError) Error() string {
	return strings.Join(e.errorStrings, "\n")
}
