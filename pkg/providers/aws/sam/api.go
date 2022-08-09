package sam

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type API struct {
	types2.Metadata
	Name                types2.StringValue
	TracingEnabled      types2.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	types2.Metadata
	ApiKeyRequired types2.BoolValue
}

type AccessLogging struct {
	types2.Metadata
	CloudwatchLogGroupARN types2.StringValue
}

type DomainConfiguration struct {
	types2.Metadata
	Name           types2.StringValue
	SecurityPolicy types2.StringValue
}

type RESTMethodSettings struct {
	types2.Metadata
	CacheDataEncrypted types2.BoolValue
	LoggingEnabled     types2.BoolValue
	DataTraceEnabled   types2.BoolValue
	MetricsEnabled     types2.BoolValue
}
