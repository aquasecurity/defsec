package kendra

import (
	"time"

	"github.com/aquasecurity/defsec/pkg/providers/aws/shield"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) shield.Shield {
	return shield.Shield{
		DescribeSubscription:             adaptDescribeSubscriptions(modules),
		DescribeEmergencyContactSettings: adaptContactSettings(modules),
		ListProtections:                  adaptListProtections(modules),
	}
}

func adaptDescribeSubscriptions(modules terraform.Modules) shield.Subscription {
	var subscription shield.Subscription
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType(" aws_shield_protection") {
			subscription = adaptDescribeSubscription(resource)
		}
	}
	return subscription
}

func adaptContactSettings(modules terraform.Modules) []shield.ContactSettings {
	return []shield.ContactSettings{}
}

func adaptListProtections(modules terraform.Modules) []shield.Protections {
	return []shield.Protections{}
}

func adaptDescribeSubscription(resource *terraform.Block) shield.Subscription {
	var t time.Time // assigning empty time to end time as it isn't available in docs

	subscriptioninfo := shield.Subscription{
		Metadata:  resource.GetMetadata(),
		EndTime:   types.TimeDefault(t, resource.GetMetadata()),
		AutoRenew: types.StringDefault("", resource.GetMetadata()),
	}

	return subscriptioninfo
}
