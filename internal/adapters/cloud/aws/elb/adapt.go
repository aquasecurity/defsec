package elb

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	apiV1 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	api "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

type adapter struct {
	*aws.RootAdapter
	api   *api.Client
	apiV1 *apiV1.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "elb"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	a.apiV1 = apiV1.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ELB.LoadBalancers, err = a.getLoadBalancers()
	if err != nil {
		return err
	}

	state.AWS.ELB.TargetGroups, err = a.getTargetGroups()
	if err != nil {
		return err
	}

	state.AWS.ELB.LoadBalancersV1, err = a.getLoadBalancersV1()
	if err != nil {
		return err
	}

	state.AWS.ELB.LoadBalancerPolicies, err = a.getLoadBalancersPolicies()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getLoadBalancers() ([]elb.LoadBalancer, error) {

	a.Tracker().SetServiceLabel("Discovering load balancers...")

	var apiLoadBalancers []types.LoadBalancer
	var input api.DescribeLoadBalancersInput
	for {
		output, err := a.api.DescribeLoadBalancers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiLoadBalancers = append(apiLoadBalancers, output.LoadBalancers...)
		a.Tracker().SetTotalResources(len(apiLoadBalancers))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting load balancers...")
	return concurrency.Adapt(apiLoadBalancers, a.RootAdapter, a.adaptLoadBalancer), nil
}

func (a *adapter) adaptLoadBalancer(apiLoadBalancer types.LoadBalancer) (*elb.LoadBalancer, error) {
	metadata := a.CreateMetadataFromARN(*apiLoadBalancer.LoadBalancerArn)

	var attributes []elb.AttibuteV2
	var dropInvalidHeaders bool
	{
		// routing.http.drop_invalid_header_fields.enabled
		output, err := a.api.DescribeLoadBalancerAttributes(a.Context(), &api.DescribeLoadBalancerAttributesInput{
			LoadBalancerArn: apiLoadBalancer.LoadBalancerArn,
		})
		if err != nil {
			return nil, err
		}

		for _, attr := range output.Attributes {
			if attr.Key != nil && *attr.Key == "routing.http.drop_invalid_header_fields.enabled" {
				dropInvalidHeaders = attr.Value != nil && *attr.Value == "true"
				break
			}
			attributes = append(attributes, elb.AttibuteV2{
				Metadata: metadata,
				Key:      defsecTypes.String(*attr.Key, metadata),
				Value:    defsecTypes.String(*attr.Value, metadata),
			})
		}
	}

	var listeners []elb.Listener
	{
		input := api.DescribeListenersInput{
			LoadBalancerArn: apiLoadBalancer.LoadBalancerArn,
		}
		for {
			output, err := a.api.DescribeListeners(a.Context(), &input)
			if err != nil {
				return nil, err
			}
			for _, listener := range output.Listeners {
				metadata := a.CreateMetadataFromARN(*listener.ListenerArn)

				var actions []elb.Action
				for _, action := range listener.DefaultActions {
					actions = append(actions, elb.Action{
						Metadata: metadata,
						Type:     defsecTypes.String(string(action.Type), metadata),
					})
				}

				sslPolicy := defsecTypes.StringDefault("", metadata)
				if listener.SslPolicy != nil {
					sslPolicy = defsecTypes.String(*listener.SslPolicy, metadata)
				}

				var certificates []elb.Certificate
				for _, certificate := range listener.Certificates {
					certificates = append(certificates, elb.Certificate{
						Metadata: metadata,
						Arn:      defsecTypes.String(*certificate.CertificateArn, metadata),
					})
				}

				listeners = append(listeners, elb.Listener{
					Metadata:       metadata,
					Protocol:       defsecTypes.String(string(listener.Protocol), metadata),
					TLSPolicy:      sslPolicy,
					Certificates:   certificates,
					DefaultActions: actions,
				})
			}
			if output.NextMarker == nil {
				break
			}
			input.Marker = output.NextMarker
		}
	}

	return &elb.LoadBalancer{
		Metadata:                metadata,
		Type:                    defsecTypes.String(string(apiLoadBalancer.Type), metadata),
		DropInvalidHeaderFields: defsecTypes.Bool(dropInvalidHeaders, metadata),
		Internal:                defsecTypes.Bool(apiLoadBalancer.Scheme == types.LoadBalancerSchemeEnumInternal, metadata),
		Listeners:               listeners,
		Attibute:                attributes,
	}, nil
}

func (a *adapter) getTargetGroups() ([]elb.TargetGroup, error) {

	a.Tracker().SetServiceLabel("Discovering target groups...")

	var apiTargetGroup []types.TargetGroup
	var input api.DescribeTargetGroupsInput
	for {
		output, err := a.api.DescribeTargetGroups(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiTargetGroup = append(apiTargetGroup, output.TargetGroups...)
		a.Tracker().SetTotalResources(len(apiTargetGroup))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting target groups...")
	return concurrency.Adapt(apiTargetGroup, a.RootAdapter, a.adaptTargetGroup), nil
}

func (a *adapter) adaptTargetGroup(apigroup types.TargetGroup) (*elb.TargetGroup, error) {
	metadata := a.CreateMetadataFromARN(*apigroup.TargetGroupArn)

	var attributes []elb.AttibuteV2
	{
		output, err := a.api.DescribeTargetGroupAttributes(a.Context(), &api.DescribeTargetGroupAttributesInput{
			TargetGroupArn: apigroup.TargetGroupArn,
		})
		if err != nil {
			return nil, err
		}
		for _, attr := range output.Attributes {
			attributes = append(attributes, elb.AttibuteV2{
				Metadata: metadata,
				Key:      defsecTypes.String(*attr.Key, metadata),
				Value:    defsecTypes.String(*attr.Value, metadata),
			})
		}
	}

	var targethealth []elb.TargetHealth
	{
		output, err := a.api.DescribeTargetHealth(a.Context(), &api.DescribeTargetHealthInput{
			TargetGroupArn: apigroup.TargetGroupArn,
		})

		if err != nil {
			return nil, err
		}

		for _, TH := range output.TargetHealthDescriptions {

			var id, state string
			if TH.Target != nil || TH.Target.Id != nil {
				id = *TH.Target.Id
			}
			if TH.TargetHealth != nil {
				state = string(TH.TargetHealth.State)
			}
			targethealth = append(targethealth, elb.TargetHealth{
				Metadata:          metadata,
				TargetId:          defsecTypes.String(id, metadata),
				TargetHealthState: defsecTypes.String(state, metadata),
			})
		}
	}

	return &elb.TargetGroup{
		Metadata:     metadata,
		Attribute:    attributes,
		TargetHealth: targethealth,
	}, nil
}
