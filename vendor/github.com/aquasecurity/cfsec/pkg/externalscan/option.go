package externalscan

import "github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"

type Option func(e *ExternalScanner)

func OptionIncludePassed() Option {
	return func(e *ExternalScanner) {
		e.internalOptions = append(e.internalOptions, scanner.OptionIncludePassed())
	}
}

func OptionDebugEnabled() Option {
	return func(e *ExternalScanner) {
		e.debugEnabled = true
	}
}
