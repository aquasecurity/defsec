package parser

import (
	"fmt"
	"strings"
)

type ErrNotCloudFormation struct {
	source string
}

func NewErrNotCloudFormation(source string) *ErrNotCloudFormation {
	return &ErrNotCloudFormation{
		source: source,
	}
}

func (e *ErrNotCloudFormation) Error() string {
	return fmt.Sprintf("The file %s is not CloudFormation", e.source)
}

type ErrInvalidContent struct {
	source string
	err    error
}

func NewErrInvalidContent(source string, err error) *ErrInvalidContent {
	return &ErrInvalidContent{
		source: source,
		err:    err,
	}
}
func (e *ErrInvalidContent) Error() string {
	return fmt.Sprintf("Invalid content in file: %s. Error: %v", e.source, e.err)
}

func (e *ErrInvalidContent) Reason() error {
	return e.err
}

type ErrParsingErrors struct {
	errs       []error
	errStrings []string
}

func NewErrParsingErrors(errs []error) *ErrParsingErrors {
	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return &ErrParsingErrors{
		errs:       errs,
		errStrings: errStrings,
	}
}

func (e *ErrParsingErrors) Error() string {
	return fmt.Sprintf("There were parsing errors:\n %s", strings.Join(e.errStrings, "\n"))
}
