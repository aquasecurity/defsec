package config

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func getConfigurationAggregator(ctx parser.FileContext) config.ConfigurationAggregrator {

	aggregator := config.ConfigurationAggregrator{
		Metadata:         types2.NewUnmanagedMetadata(),
		SourceAllRegions: types2.BoolDefault(false, ctx.Metadata()),
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

func isSourcingAllRegions(r *parser.Resource) types2.BoolValue {
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
	return types2.BoolDefault(false, r.Metadata())
}
