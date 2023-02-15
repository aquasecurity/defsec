package elb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getLoadBalancersV1(ctx parser.FileContext) (loadbalancers []elb.LoadBalancerV1) {

	loadBalanacerResources := ctx.GetResourcesByType("AWS::ElasticLoadBalancing::LoadBalancer")

	for _, r := range loadBalanacerResources {

		var listener []elb.ListenerV1
		for _, l := range r.GetProperty("Listeners").AsList() {
			listener = append(listener, elb.ListenerV1{
				Metadata: l.Metadata(),
				Protocol: r.GetStringProperty("Protocol"),
			})
		}
		var ins []elb.Instance
		for _, l := range r.GetProperty("Instances").AsList() {
			ins = append(ins, elb.Instance{
				Metadata: l.Metadata(),
				Id:       types.String(l.AsString(), l.Metadata()),
			})
		}
		LB := elb.LoadBalancerV1{
			Metadata: r.Metadata(),
			Name:     r.GetStringProperty("LoadBalancerName"),
			DNSName:  r.GetStringProperty("DNSName"),
			Listener: listener,
			Attributes: elb.Attibute{
				Metadata:                      r.Metadata(),
				ConnectionDrainingEnabled:     r.GetBoolProperty("ConnectionDrainingPolicy.Enabled"),
				CrossZoneLoadBalancingEnabled: r.GetBoolProperty("CrossZone"),
				AccessLogEnabled:              r.GetBoolProperty("AccessLoggingPolicy.Enabled"),
			},
			Instances: ins,
		}
		loadbalancers = append(loadbalancers, LB)
	}
	return loadbalancers
}

func getLoadBalancersPolicy(ctx parser.FileContext) (policies []elb.LoadBalancerPolicy) {
	loadBalanacerResources := ctx.GetResourcesByType("AWS::ElasticLoadBalancing::LoadBalancer")

	for _, r := range loadBalanacerResources {
		for _, p := range r.GetProperty("Policy").AsList() {

			var attributes []elb.PolicyAttributeDescription
			for _, attr := range p.GetProperty("").AsList() {
				attributes = append(attributes, elb.PolicyAttributeDescription{
					Metadata: p.Metadata(),
					Name:     types.String(attr.AsMap()["Name"].AsString(), attr.Metadata()),
					Value:    types.String(attr.AsMap()["Value"].AsString(), attr.Metadata()),
				})
			}

			policies = append(policies, elb.LoadBalancerPolicy{
				Metadata:                    p.Metadata(),
				PolicyAttributeDescriptions: attributes,
			})
		}
	}
	return policies
}
