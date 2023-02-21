package devopsguru

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/devopsguru"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) devopsguru.Devopsguru {
	return devopsguru.Devopsguru{
		NotificationChannels: getChannel(cfFile),
	}
}
