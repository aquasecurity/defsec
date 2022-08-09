package sam

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type HttpAPI struct {
	types2.Metadata
	Name                 types2.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	types2.Metadata
	LoggingEnabled         types2.BoolValue
	DataTraceEnabled       types2.BoolValue
	DetailedMetricsEnabled types2.BoolValue
}
