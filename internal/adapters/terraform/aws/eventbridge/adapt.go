package eventbridge

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eventbridge"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) eventbridge.EventBridge {
	return eventbridge.EventBridge{
		Buses: adaptBuses(modules),
		Rules: adaptRules(modules),
	}
}

func adaptBuses(modules terraform.Modules) []eventbridge.Bus {
	var Buses []eventbridge.Bus
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_event_bus") {
			Buses = append(Buses, adaptBus(resource, module))
		}
	}
	return Buses
}

func adaptBus(resource *terraform.Block, module *terraform.Module) eventbridge.Bus {

	var policy types.StringValue
	policyRes := module.GetReferencingResources(resource, " aws_cloudwatch_event_bus_policy", "event_bus_name")
	for _, r := range policyRes {
		policy = r.GetAttribute("policy").AsStringValueOrDefault("", r)
	}
	return eventbridge.Bus{
		Metadata: resource.GetMetadata(),
		Policy:   policy,
	}
}

func adaptRules(modules terraform.Modules) []eventbridge.Rule {
	var rules []eventbridge.Rule
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_event_rule") {
			rules = append(rules, eventbridge.Rule{
				Metadata: resource.GetMetadata(),
			})
		}
	}
	return rules
}
