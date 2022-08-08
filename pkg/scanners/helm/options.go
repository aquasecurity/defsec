package helm

import (
	"github.com/aquasecurity/defsec/pkg/scanners/helm/parser"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableHelmScanner interface {
	options.ConfigurableScanner
	AddParserOptions(options ...options.ParserOption)
}

func ScannerWithValuesFile(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(ConfigurableHelmScanner); ok {
			helmScanner.AddParserOptions(parser.OptionWithValuesFile(paths...))
		}
	}
}

func ScannerWithValues(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(ConfigurableHelmScanner); ok {
			helmScanner.AddParserOptions(parser.OptionWithValues(values...))
		}
	}
}

func ScannerWithFileValues(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(ConfigurableHelmScanner); ok {
			helmScanner.AddParserOptions(parser.OptionWithFileValues(values...))
		}
	}
}

func ScannerWithStringValues(values ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if helmScanner, ok := s.(ConfigurableHelmScanner); ok {
			helmScanner.AddParserOptions(parser.OptionWithStringValues(values...))
		}
	}
}
