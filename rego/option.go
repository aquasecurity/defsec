package rego

import "io"

type Option func(s *Scanner)

// OptionWithDebug - pass the scanner an io.Writer to log debug messages to
func OptionWithDebug(debugWriter io.Writer) func(s *Scanner) {
	return func(s *Scanner) {
		s.debugWriter = debugWriter
	}
}
