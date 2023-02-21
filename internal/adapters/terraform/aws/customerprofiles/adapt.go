package customerprofiles

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/customerprofiles"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) customerprofiles.Customerprofiles {
	return customerprofiles.Customerprofiles{
		Domains: nil,
	}
}
