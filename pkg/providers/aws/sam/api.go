package sam

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type API struct {
	defsecTypes.Metadata
	Name                defsecTypes.StringValue
	TracingEnabled      defsecTypes.BoolValue
	DomainConfiguration DomainConfiguration
	AccessLogging       AccessLogging
	RESTMethodSettings  RESTMethodSettings
}

type ApiAuth struct {
	defsecTypes.Metadata
	ApiKeyRequired defsecTypes.BoolValue
}

type AccessLogging struct {
	defsecTypes.Metadata
	CloudwatchLogGroupARN defsecTypes.StringValue
}

type DomainConfiguration struct {
	defsecTypes.Metadata
	Name           defsecTypes.StringValue
	SecurityPolicy defsecTypes.StringValue
}

type RESTMethodSettings struct {
	defsecTypes.Metadata
	CacheDataEncrypted defsecTypes.BoolValue
	LoggingEnabled     defsecTypes.BoolValue
	DataTraceEnabled   defsecTypes.BoolValue
	MetricsEnabled     defsecTypes.BoolValue
}
