package kubernetes

import (
	"io"

	"github.com/aquasecurity/defsec/pkg/scanners/kubernetes/parser"
)

type Option func(s *Scanner)

// OptionWithDebug - pass the scanner an io.Writer to log debug messages to
func OptionWithDebug(debugWriter io.Writer) func(s *Scanner) {
	return func(s *Scanner) {
		s.debugWriter = debugWriter
	}
}

func OptionWithPolicyDirs(paths ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyDirs = paths
	}
}

func OptionWithPolicyReaders(readers ...io.Reader) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyReaders = readers
	}
}

func OptionWithDataDirs(paths ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.dataDirs = paths
	}
}

// OptionWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func OptionWithPolicyNamespaces(namespaces ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyNamespaces = namespaces
	}
}

func OptionWithTrace(w io.Writer) Option {
	return func(s *Scanner) {
		s.traceWriter = w
	}
}

func OptionWithParser(p *parser.Parser) Option {
	return func(s *Scanner) {
		s.parser = p
	}
}

func OptionWithPerResultTracing() Option {
	return func(s *Scanner) {
		s.traceWriter = io.Discard
	}
}
