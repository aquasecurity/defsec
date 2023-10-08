package config

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
	Rules                    []Rule
	RecorderStatus           []RecorderStatus
	Recorders                []Recorder
	DeliveryChannels         []DeliveryChannel
	ResourceCounts           []ResourceCount
}

type ConfigurationAggregrator struct {
	Metadata         defsecTypes.Metadata
	SourceAllRegions defsecTypes.BoolValue
}

type Rule struct {
	Metadata        defsecTypes.Metadata
	Arn             defsecTypes.StringValue
	EvaluateResults []EvaluateResult
}

type EvaluateResult struct {
	Metadata defsecTypes.Metadata
}

type RecorderStatus struct {
	Metadata   defsecTypes.Metadata
	LastStatus defsecTypes.StringValue
	Recording  defsecTypes.BoolValue
}

type Recorder struct {
	Metadata                   defsecTypes.Metadata
	IncludeGlobalResourceTypes defsecTypes.BoolValue
}

type DeliveryChannel struct {
	Metadata   defsecTypes.Metadata
	BucketName defsecTypes.StringValue
}

type ResourceCount struct {
	Metadata     defsecTypes.Metadata
	ResourceType defsecTypes.StringValue
}
