package parser

import "io"

type Option func(p *Parser)

func OptionWithDebugWriter(w io.Writer) Option {
	return func(p *Parser) {
		p.debugWriter = w
	}
}

func OptionWithTFVarsPaths(paths []string) Option {
	return func(p *Parser) {
		p.tfvarsPaths = paths
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(p *Parser) {
		p.stopOnHCLError = stop
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(p *Parser) {
		p.workspaceName = workspaceName
	}
}

func OptionWithDownloads(allowed bool) Option {
	return func(p *Parser) {
		p.allowDownloads = allowed
	}
}
