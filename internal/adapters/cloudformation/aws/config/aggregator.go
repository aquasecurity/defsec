package config

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getConfigurationAggregator(ctx parser.FileContext) config.ConfigurationAggregrator {

	aggregator := config.ConfigurationAggregrator{
		Metadata:         defsecTypes.NewUnmanagedMetadata(),
		SourceAllRegions: defsecTypes.BoolDefault(false, ctx.Metadata()),
	}

	aggregatorResources := ctx.GetResourcesByType("AWS::Config::ConfigurationAggregator")

	if len(aggregatorResources) == 0 {
		return aggregator
	}

	return config.ConfigurationAggregrator{
		Metadata:         aggregatorResources[0].Metadata(),
		SourceAllRegions: isSourcingAllRegions(aggregatorResources[0]),
	}
}

func isSourcingAllRegions(r *parser.Resource) defsecTypes.BoolValue {
	accountProp := r.GetProperty("AccountAggregationSources")
	orgProp := r.GetProperty("OrganizationAggregationSource")

	if accountProp.IsNotNil() && accountProp.IsList() {
		for _, a := range accountProp.AsList() {
			regionsProp := a.GetProperty("AllAwsRegions")
			if regionsProp.IsNil() || regionsProp.IsBool() {
				return regionsProp.AsBoolValue()
			}
		}
	}

	if orgProp.IsNotNil() {
		regionsProp := orgProp.GetProperty("AllAwsRegions")
		if regionsProp.IsBool() {
			return regionsProp.AsBoolValue()
		}
	}

	// nothing is set or resolvable so its got to be false
	return defsecTypes.BoolDefault(false, r.Metadata())
}

func getConfigRule(ctx parser.FileContext) []config.Rule {

	res := ctx.GetResourcesByType("AWS::Config::ConfigRule")
	var rules []config.Rule
	for _, r := range res {
		rules = append(rules, config.Rule{
			Metadata:        r.Metadata(),
			Arn:             r.GetStringProperty("Arn"),
			EvaluateResults: nil,
		})
	}
	return rules
}

func getRecorders(ctx parser.FileContext) []config.Recorder {

	res := ctx.GetResourcesByType("AWS::Config::ConfigurationRecorder")
	var recorders []config.Recorder
	for _, r := range res {
		recorders = append(recorders, config.Recorder{
			Metadata:                   r.Metadata(),
			IncludeGlobalResourceTypes: r.GetBoolProperty("RecordingGroup.IncludeGlobalResourceTypes"),
		})
	}
	return recorders
}

func getDeliveryChannel(ctx parser.FileContext) []config.DeliveryChannel {

	res := ctx.GetResourcesByType("AWS::Config::DeliveryChannel")
	var channels []config.DeliveryChannel
	for _, r := range res {
		channels = append(channels, config.DeliveryChannel{
			Metadata:   r.Metadata(),
			BucketName: r.GetStringProperty("S3BucketName"),
		})
	}
	return channels
}
