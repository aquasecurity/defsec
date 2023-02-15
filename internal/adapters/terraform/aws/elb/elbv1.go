package elb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func (a *adapter) adaptLoadBalancersV1(modules terraform.Modules) []elb.LoadBalancerV1 {
	var loadBalancers []elb.LoadBalancerV1

	for _, resource := range modules.GetResourcesByType("aws_elb") {
		loadBalancers = append(loadBalancers, a.adaptLoadBalancerV1(resource))
	}
	return loadBalancers
}

func (a *adapter) adaptLoadBalancerV1(resource *terraform.Block) elb.LoadBalancerV1 {

	var ins []elb.Instance
	for _, i := range resource.GetAttribute("instances").AsStringValues() {
		ins = append(ins, elb.Instance{
			Metadata: i.GetMetadata(),
			Id:       i,
		})
	}

	var listener []elb.ListenerV1
	for _, l := range resource.GetBlocks("listener") {
		listener = append(listener, elb.ListenerV1{
			Metadata: l.GetMetadata(),
			Protocol: l.GetAttribute("lb_protocol").AsStringValueOrDefault("", l),
		})
	}

	var acclog defsecTypes.BoolValue
	if acclogblock := resource.GetBlock(" access_logs"); acclogblock.IsNotNil() {
		acclogattr := acclogblock.GetAttribute("enabled")
		acclog = acclogattr.AsBoolValueOrDefault(true, resource)

	}
	return elb.LoadBalancerV1{
		Metadata:  resource.GetMetadata(),
		Name:      resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		DNSName:   resource.GetAttribute("dns_name").AsStringValueOrDefault("", resource),
		Instances: ins,
		Listener:  listener,
		Attributes: elb.Attibute{
			Metadata:                      resource.GetMetadata(),
			AccessLogEnabled:              acclog,
			CrossZoneLoadBalancingEnabled: resource.GetAttribute("cross_zone_load_balancing").AsBoolValueOrDefault(true, resource),
			ConnectionDrainingEnabled:     resource.GetAttribute("connection_draining").AsBoolValueOrDefault(false, resource),
		},
	}
}

func (a *adapter) adaptLoadBalancersPolicies(modules terraform.Modules) []elb.LoadBalancerPolicy {
	var loadBalancerPolicies []elb.LoadBalancerPolicy

	for _, resource := range modules.GetResourcesByType(" aws_load_balancer_policy") {
		loadBalancerPolicies = append(loadBalancerPolicies, a.adaptLoadBalancerPolicy(resource))
	}
	return loadBalancerPolicies
}

func (a *adapter) adaptLoadBalancerPolicy(resource *terraform.Block) elb.LoadBalancerPolicy {

	var attr []elb.PolicyAttributeDescription
	for _, a := range resource.GetBlocks("policy_attribute") {
		attr = append(attr, elb.PolicyAttributeDescription{
			Metadata: a.GetMetadata(),
			Name:     a.GetAttribute("name").AsStringValueOrDefault("", a),
			Value:    a.GetAttribute("value").AsStringValueOrDefault("", a),
		})
	}
	return elb.LoadBalancerPolicy{
		Metadata:                    resource.GetMetadata(),
		PolicyAttributeDescriptions: attr,
	}
}
