package terraformplan

import (
	"github.com/aquasecurity/defsec/pkg/scanners/terraformplan/parser"
)

type Option func(s *Scanner)

func OptionStopOnHCLError(stop bool) Option {
	return func(s *Scanner) {
		s.parserOpt = append(s.parserOpt, parser.OptionStopOnHCLError(stop))
	}
}
