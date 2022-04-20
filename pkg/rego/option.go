package rego

import "io"

type Option func(s *Scanner)

// OptionWithDebug - pass the scanner an io.Writer to log debug messages to
func OptionWithDebug(debugWriter io.Writer) func(s *Scanner) {
	return func(s *Scanner) {
		s.debugWriter = debugWriter
	}
}

// OptionWithTrace - specify an io.Writer for rego tracing
func OptionWithTrace(w io.Writer) func(s *Scanner) {
	return func(s *Scanner) {
		s.traceWriter = w
	}
}

// OptionWithPerResultTracing - sets up tracing on a per-result basis with no main stream
func OptionWithPerResultTracing() func(s *Scanner) {
	return func(s *Scanner) {
		s.traceWriter = io.Discard
	}
}

func OptionWithPolicyNamespaces(includeDefaults bool, namespaces ...string) func(s *Scanner) {
	return func(s *Scanner) {
		if !includeDefaults {
			s.ruleNamespaces = make(map[string]struct{})
		}
		for _, namespace := range namespaces {
			s.ruleNamespaces[namespace] = struct{}{}
		}
	}
}

func OptionWithDataDirs(dirs ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.dataDirs = dirs
	}
}
