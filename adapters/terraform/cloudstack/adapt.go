package cloudstack

import (
	"github.com/aquasecurity/defsec/adapters/terraform/cloudstack/compute"
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/provider/cloudstack"
)

func Adapt(modules terraform.Modules) cloudstack.CloudStack {
	return cloudstack.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
