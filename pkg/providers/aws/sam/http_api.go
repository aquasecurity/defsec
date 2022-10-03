package sam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type HttpAPI struct {
	Metadata             defsecTypes.Metadata
	Name                 defsecTypes.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	Metadata               defsecTypes.Metadata
	LoggingEnabled         defsecTypes.BoolValue
	DataTraceEnabled       defsecTypes.BoolValue
	DetailedMetricsEnabled defsecTypes.BoolValue
}
