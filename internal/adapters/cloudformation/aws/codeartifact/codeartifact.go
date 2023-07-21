package codeartifact

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codeartifact"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) codeartifact.Codeartifact {
	return codeartifact.Codeartifact{
		Domains: getDomain(cfFile),
	}
}
