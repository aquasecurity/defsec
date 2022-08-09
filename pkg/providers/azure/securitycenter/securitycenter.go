package securitycenter

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	types2.Metadata
	EnableAlertNotifications types2.BoolValue
	Phone                    types2.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	types2.Metadata
	Tier types2.StringValue
}
