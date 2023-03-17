package terraform

import (
	"github.com/aquasecurity/defsec/pkg/providers/terraform/module"
	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
)

type Terraform struct {
	Modules     []module.Module
	Provisioner provisioner.Provisioner
}
