package config

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) config.Config {
	return config.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
		Rules:                    adaptConfigRule(modules),
		RecorderStatus:           adaptRecordersStatus(modules),
		Recorders:                adaptRecorders(modules),
		DeliveryChannels:         adaptDeliveryChannel(modules),
		ResourceCounts:           nil,
	}
}

func adaptConfigurationAggregrator(modules terraform.Modules) config.ConfigurationAggregrator {
	configurationAggregrator := config.ConfigurationAggregrator{
		Metadata:         defsecTypes.NewUnmanagedMetadata(),
		SourceAllRegions: defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
	}

	for _, resource := range modules.GetResourcesByType("aws_config_configuration_aggregator") {
		configurationAggregrator.Metadata = resource.GetMetadata()
		aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
		if aggregationBlock.IsNil() {
			configurationAggregrator.SourceAllRegions = defsecTypes.Bool(false, resource.GetMetadata())
		} else {
			allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
			allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
			configurationAggregrator.SourceAllRegions = allRegionsVal
		}
	}
	return configurationAggregrator
}

func adaptRecorders(modules terraform.Modules) []config.Recorder {
	var recorders []config.Recorder
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_config_configuration_recorder") {
			var resourceType defsecTypes.BoolValue
			if recordingGroupBlock := resource.GetBlock("recording_group"); recordingGroupBlock.IsNotNil() {
				resourceType = recordingGroupBlock.GetAttribute("include_global_resource_types").AsBoolValueOrDefault(false, recordingGroupBlock)
			}
			recorders = append(recorders, config.Recorder{
				Metadata:                   resource.GetMetadata(),
				IncludeGlobalResourceTypes: resourceType,
			})
		}
	}
	return recorders
}

func adaptConfigRule(modules terraform.Modules) []config.Rule {
	var rules []config.Rule
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_config_config_rule") {
			rules = append(rules, config.Rule{
				Metadata:        resource.GetMetadata(),
				Arn:             resource.GetAttribute("arn").AsStringValueOrDefault("", resource),
				EvaluateResults: nil,
			})
		}
	}
	return rules
}

func adaptRecordersStatus(modules terraform.Modules) []config.RecorderStatus {
	var recorderStatus []config.RecorderStatus
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_config_configuration_recorder_status") {
			recorderStatus = append(recorderStatus, config.RecorderStatus{
				Metadata:   resource.GetMetadata(),
				LastStatus: defsecTypes.String("", resource.GetMetadata()),
				Recording:  defsecTypes.Bool(false, resource.GetMetadata()),
			})
		}
	}
	return recorderStatus
}

func adaptDeliveryChannel(modules terraform.Modules) []config.DeliveryChannel {
	var channels []config.DeliveryChannel
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_config_delivery_channel") {
			channels = append(channels, config.DeliveryChannel{
				Metadata:   resource.GetMetadata(),
				BucketName: resource.GetAttribute("s3_bucket_name").AsStringValueOrDefault("", resource),
			})
		}
	}
	return channels
}
