package shield

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/shield"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) shield.Shield {
	var subscription shield.Subscription
	var Protections []shield.Protections
	var ContactSettings []shield.ContactSettings
	return shield.Shield{
		DescribeSubscription:             subscription,
		ListProtections:                  Protections,
		DescribeEmergencyContactSettings: ContactSettings,
	}
}
