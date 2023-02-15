package elb

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	apiV1 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
)

func (a *adapter) getLoadBalancersV1() ([]elb.LoadBalancerV1, error) {

	a.Tracker().SetServiceLabel("Discovering load balancers...")

	var apiLoadBalancers []types.LoadBalancerDescription
	var input apiV1.DescribeLoadBalancersInput
	for {
		output, err := a.apiV1.DescribeLoadBalancers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiLoadBalancers = append(apiLoadBalancers, output.LoadBalancerDescriptions...)
		a.Tracker().SetTotalResources(len(apiLoadBalancers))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting load balancers...")
	return concurrency.Adapt(apiLoadBalancers, a.RootAdapter, a.adaptLoadBalancerV1), nil
}

func (a *adapter) adaptLoadBalancerV1(loadbalancer types.LoadBalancerDescription) (*elb.LoadBalancerV1, error) {

	metadata := a.CreateMetadata(*loadbalancer.LoadBalancerName)

	var listener []elb.ListenerV1
	for _, lis := range loadbalancer.ListenerDescriptions {
		listener = append(listener, elb.ListenerV1{
			Metadata: metadata,
			Protocol: defsecTypes.String(*lis.Listener.Protocol, metadata),
		})
	}

	var instances []elb.Instance
	for _, ins := range loadbalancer.Instances {
		instances = append(instances, elb.Instance{
			Metadata: metadata,
			Id:       defsecTypes.String(*ins.InstanceId, metadata),
		})
	}

	var attributes elb.Attibute
	{
		output, err := a.apiV1.DescribeLoadBalancerAttributes(a.Context(), &apiV1.DescribeLoadBalancerAttributesInput{
			LoadBalancerName: loadbalancer.LoadBalancerName,
		})
		if err != nil {
			return nil, err
		}
		var acclog, conndraining, crosszone bool
		if output.LoadBalancerAttributes.AccessLog != nil {
			acclog = output.LoadBalancerAttributes.AccessLog.Enabled
		}
		if output.LoadBalancerAttributes.ConnectionDraining != nil {
			conndraining = output.LoadBalancerAttributes.ConnectionDraining.Enabled
		}
		if output.LoadBalancerAttributes.CrossZoneLoadBalancing != nil {
			crosszone = output.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled
		}
		attributes = elb.Attibute{
			Metadata:                      metadata,
			AccessLogEnabled:              defsecTypes.Bool(acclog, metadata),
			CrossZoneLoadBalancingEnabled: defsecTypes.Bool(crosszone, metadata),
			ConnectionDrainingEnabled:     defsecTypes.Bool(conndraining, metadata),
		}
	}

	return &elb.LoadBalancerV1{
		Metadata:   metadata,
		Name:       defsecTypes.String(*loadbalancer.LoadBalancerName, metadata),
		DNSName:    defsecTypes.String(*loadbalancer.DNSName, metadata),
		Listener:   listener,
		Attributes: attributes,
		Instances:  instances,
	}, nil
}

func (a *adapter) getLoadBalancersPolicies() ([]elb.LoadBalancerPolicy, error) {

	a.Tracker().SetServiceLabel("Discovering load balancer policy...")

	var apiLoadBalancers []types.PolicyDescription
	var input apiV1.DescribeLoadBalancerPoliciesInput
	for {
		output, err := a.apiV1.DescribeLoadBalancerPolicies(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiLoadBalancers = append(apiLoadBalancers, output.PolicyDescriptions...)
		a.Tracker().SetTotalResources(len(apiLoadBalancers))
		if output.PolicyDescriptions == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting load balancer policies...")
	return concurrency.Adapt(apiLoadBalancers, a.RootAdapter, a.adaptLoadBalancerPolicy), nil
}

func (a *adapter) adaptLoadBalancerPolicy(policy types.PolicyDescription) (*elb.LoadBalancerPolicy, error) {
	metadata := a.CreateMetadata(*policy.PolicyName)

	var attributes []elb.PolicyAttributeDescription
	for _, des := range policy.PolicyAttributeDescriptions {
		attributes = append(attributes, elb.PolicyAttributeDescription{
			Metadata: metadata,
			Name:     defsecTypes.String(*des.AttributeName, metadata),
			Value:    defsecTypes.String(*des.AttributeValue, metadata),
		})
	}

	return &elb.LoadBalancerPolicy{
		Metadata:                    metadata,
		PolicyAttributeDescriptions: attributes,
	}, nil
}
