package securitycenter

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	defsecTypes.Metadata
	EnableAlertNotifications defsecTypes.BoolValue
	Phone                    defsecTypes.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	defsecTypes.Metadata
	Tier defsecTypes.StringValue
}
