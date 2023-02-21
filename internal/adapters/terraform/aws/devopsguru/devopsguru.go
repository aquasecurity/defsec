package devopsguru

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/devopsguru"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) devopsguru.Devopsguru {
	return devopsguru.Devopsguru{
		NotificationChannels: nil,
	}
}
