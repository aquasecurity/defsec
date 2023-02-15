package elb

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elb"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getLoadBalancers(ctx parser.FileContext) (loadbalancers []elb.LoadBalancer) {

	loadBalanacerResources := ctx.GetResourcesByType("AWS::ElasticLoadBalancingV2::LoadBalancer")

	for _, r := range loadBalanacerResources {
		lb := elb.LoadBalancer{
			Metadata:                r.Metadata(),
			Type:                    r.GetStringProperty("Type", "application"),
			DropInvalidHeaderFields: checkForDropInvalidHeaders(r),
			Internal:                isInternal(r),
			Listeners:               getListeners(r, ctx),
			Attibute:                getattributes(r),
		}
		loadbalancers = append(loadbalancers, lb)
	}

	return loadbalancers
}

func getTargetGroups(ctx parser.FileContext) (targetgroups []elb.TargetGroup) {
	targetres := ctx.GetResourcesByType("")

	for _, r := range targetres {
		var attributes []elb.AttibuteV2
		for _, attr := range r.GetProperty("TargetGroupAttributes").AsList() {
			attributes = append(attributes, elb.AttibuteV2{
				Metadata: attr.Metadata(),
				Key:      r.GetStringProperty("Key"),
				Value:    r.GetStringProperty("Value"),
			})
		}
		targetgroup := elb.TargetGroup{
			Metadata:     r.Metadata(),
			Attribute:    attributes,
			TargetHealth: nil,
		}
		targetgroups = append(targetgroups, targetgroup)
	}
	return targetgroups
}

func getListeners(lbr *parser.Resource, ctx parser.FileContext) (listeners []elb.Listener) {

	listenerResources := ctx.GetResourcesByType("AWS::ElasticLoadBalancingV2::Listener")

	for _, r := range listenerResources {
		if r.GetStringProperty("LoadBalancerArn").Value() == lbr.ID() {

			var certificates []elb.Certificate
			for _, cer := range r.GetProperty("Certificates").AsList() {
				certificates = append(certificates, elb.Certificate{
					Metadata: cer.Metadata(),
					Arn:      cer.GetStringProperty("CertificateArn"),
				})
			}
			listener := elb.Listener{
				Metadata:       r.Metadata(),
				Protocol:       r.GetStringProperty("Protocol", "HTTP"),
				TLSPolicy:      r.GetStringProperty("SslPolicy", "ELBSecurityPolicy-2016-08"),
				DefaultActions: getDefaultListenerActions(r),
				Certificates:   certificates,
			}

			listeners = append(listeners, listener)
		}
	}
	return listeners
}

func getDefaultListenerActions(r *parser.Resource) (actions []elb.Action) {
	defaultActionsProp := r.GetProperty("DefaultActions")
	if defaultActionsProp.IsNotList() {
		return actions
	}
	for _, action := range defaultActionsProp.AsList() {
		actions = append(actions, elb.Action{
			Metadata: action.Metadata(),
			Type:     action.GetProperty("Type").AsStringValue(),
		})
	}
	return actions
}

func isInternal(r *parser.Resource) types.BoolValue {
	schemeProp := r.GetProperty("Scheme")
	if schemeProp.IsNotString() {
		return r.BoolDefault(false)
	}
	return types.Bool(schemeProp.EqualTo("internal", parser.IgnoreCase), schemeProp.Metadata())
}

func checkForDropInvalidHeaders(r *parser.Resource) types.BoolValue {
	attributesProp := r.GetProperty("LoadBalancerAttributes")
	if attributesProp.IsNotList() {
		return types.BoolDefault(false, r.Metadata())
	}

	for _, attr := range attributesProp.AsList() {
		if attr.IsNotMap() {
			continue
		}

		if attr.AsMap()["Key"].AsString() == "routing.http.drop_invalid_header_fields.enabled" {
			val := attr.AsMap()["Value"]
			if val.IsBool() {
				return val.AsBoolValue()
			}

		}
	}

	return r.BoolDefault(false)
}

func getattributes(r *parser.Resource) []elb.AttibuteV2 {
	var attributes []elb.AttibuteV2
	attributesProp := r.GetProperty("LoadBalancerAttributes")
	if attributesProp.IsNotList() {
		return attributes
	}
	for _, attr := range attributesProp.AsList() {
		attributes = append(attributes, elb.AttibuteV2{
			Metadata: attr.Metadata(),
			Key:      attr.GetStringProperty("Key"),
			Value:    attr.GetStringProperty("Value"),
		})
	}
	return attributes
}
