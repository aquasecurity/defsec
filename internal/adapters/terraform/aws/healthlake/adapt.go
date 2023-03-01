package healthlake

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/healthlake"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) healthlake.HealthLake {
	return healthlake.HealthLake{
		FHIRDatastores: nil,
	}
}
