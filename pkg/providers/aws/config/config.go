package config

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	defsecTypes.Metadata
	SourceAllRegions defsecTypes.BoolValue
}
