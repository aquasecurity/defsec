package provisioner

import (
	"github.com/aquasecurity/defsec/pkg/providers/terraform/provisioner"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) provisioner.Provisioner {
	return provisioner.Provisioner{
		Files:       adaptFiles(modules),
		LocalExecs:  adaptLocalExecs(modules),
		RemoteExecs: adaptRemoteExecs(modules),
	}
}
