package eventbridge

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/eventbridge"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getBuses(ctx parser.FileContext) []eventbridge.Bus {
	var buses []eventbridge.Bus

	busresources := ctx.GetResourcesByType("AWS::Events::EventBus")

	for _, r := range busresources {
		buses = append(buses, eventbridge.Bus{
			Metadata: r.Metadata(),
			Policy:   r.GetStringProperty("Policy"),
		})
	}
	return buses
}

func getRules(ctx parser.FileContext) []eventbridge.Rule {
	var rules []eventbridge.Rule

	ruleresources := ctx.GetResourcesByType("AWS::Events::Rule")

	for _, r := range ruleresources {
		rules = append(rules, eventbridge.Rule{
			Metadata: r.Metadata(),
		})
	}
	return rules
}
