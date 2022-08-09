package config

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	types2.Metadata
	SourceAllRegions types2.BoolValue
}
