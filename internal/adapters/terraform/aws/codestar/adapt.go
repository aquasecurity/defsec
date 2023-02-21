package codestar

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/codestar"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) codestar.CodeStar {
	return codestar.CodeStar{
		Projects: nil,
	}
}
