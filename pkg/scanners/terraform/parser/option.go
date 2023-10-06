package parser

import (
	"io/fs"

	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableTerraformParser interface {
	options.ConfigurableParser
	SetTFVarsPaths(...string)
	SetStopOnHCLError(bool)
	SetWorkspaceName(string)
	SetAllowDownloads(bool)
	SetConfigsFS(fsys fs.FS)
}

type Option func(p ConfigurableTerraformParser)

func OptionWithTFVarsPaths(paths ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetTFVarsPaths(paths...)
		}
	}
}

func OptionStopOnHCLError(stop bool) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetStopOnHCLError(stop)
		}
	}
}

func OptionWithWorkspaceName(workspaceName string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetWorkspaceName(workspaceName)
		}
	}
}

func OptionWithDownloads(allowed bool) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetAllowDownloads(allowed)
		}
	}
}

func OptionWithConfigsFS(fsys fs.FS) options.ParserOption {
	return func(s options.ConfigurableParser) {
		if p, ok := s.(ConfigurableTerraformParser); ok {
			p.SetConfigsFS(fsys)
		}
	}
}
