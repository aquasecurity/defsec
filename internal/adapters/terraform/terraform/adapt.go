package terraform

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/terraform/module"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/terraform/provisioner"
	"github.com/aquasecurity/defsec/pkg/providers/terraform"
	terraformpkg "github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraformpkg.Modules) terraform.Terraform {
	return terraform.Terraform{
		Provisioner: provisioner.Adapt(modules),
		Modules:     module.Adapt(modules),
	}
}
