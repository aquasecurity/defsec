package shield

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Shield struct {
	DescribeSubscription             Subscription
	DescribeEmergencyContactSettings []ContactSettings
	ListProtections                  []Protections
}

type Subscription struct {
	Metadata  defsecTypes.Metadata
	EndTime   defsecTypes.TimeValue
	AutoRenew defsecTypes.StringValue
}

type ContactSettings struct {
	Metadata defsecTypes.Metadata
}

type Protections struct {
	Metadata defsecTypes.Metadata
}
