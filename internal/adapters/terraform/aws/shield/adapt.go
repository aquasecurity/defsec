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
	subscription := shield.Subscription{
		Metadata:  types.NewUnmanagedMetadata(),
		EndTime:   types.TimeDefault(time.Now(), types.NewUnmanagedMetadata()),
		AutoRenew: types.StringDefault("", types.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_shield_protection") {
		subscription.Metadata = resource.GetMetadata()
		subscription.EndTime = types.TimeUnresolvable(resource.GetMetadata())
		subscription.AutoRenew = types.StringUnresolvable(resource.GetMetadata())
	}

	return subscription

}

func adaptContactSettings(modules terraform.Modules) []shield.ContactSettings {
	var contactSettings []shield.ContactSettings
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_shield_protection") {
			contactSettings = append(contactSettings, adaptSetting(resource))
		}
	}
	return contactSettings
}

func adaptSetting(resourceBlock *terraform.Block) shield.ContactSettings {
	return shield.ContactSettings{
		Metadata: resourceBlock.GetMetadata(),
	}
}

func adaptListProtections(modules terraform.Modules) []shield.Protections {
	var protections []shield.Protections
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_shield_protection") {
			protections = append(protections, adaptProtection(resource))
		}
	}
	return protections
}

func adaptProtection(resourceBlock *terraform.Block) shield.Protections {
	return shield.Protections{
		Metadata: resourceBlock.GetMetadata(),
	}
}
