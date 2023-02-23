package eventbridge

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eventbridge"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) eventbridge.EventBridge {
	return eventbridge.EventBridge{
		Buses: getBuses(cfFile),
		Rules: getRules(cfFile),
	}
}
