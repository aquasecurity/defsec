package finspace

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/finspace"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) finspace.ListEnvironements {
	return finspace.ListEnvironements{
		Environments: nil,
	}
}
