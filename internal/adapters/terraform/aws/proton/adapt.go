package proton

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/proton"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) proton.Proton {
	return proton.Proton{
		ListEnvironmentTemplates: nil,
	}
}
