package terraformplan

import (
	"io"

	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan/parser"
)

type Option func(s *Scanner)

func OptionWithDebug(w io.Writer) Option {
	return func(s *Scanner) {
		s.debugWriter = w

		s.parserOpt = append(s.parserOpt, parser.OptionWithDebugWriter(w))
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(s *Scanner) {
		s.parserOpt = append(s.parserOpt, parser.OptionStopOnHCLError(stop))
	}
}
