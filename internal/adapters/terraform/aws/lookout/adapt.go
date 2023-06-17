package lookout

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lookout"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) lookout.Lookout {
	return lookout.Lookout{
		AnomalyDetectors: nil,
		Datasets:         nil,
		Models:           nil,
	}
}
