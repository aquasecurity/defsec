package v1

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

type API struct {
	types.Metadata
	Name      types.StringValue
	Stages    []Stage
	Resources []Resource
}

type Stage struct {
	types.Metadata
	Name               types.StringValue
	AccessLogging      AccessLogging
	XRayTracingEnabled types.BoolValue
	RESTMethodSettings []RESTMethodSettings
}

type Resource struct {
	types.Metadata
	Methods []Method
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type RESTMethodSettings struct {
	types.Metadata
	Method             types.StringValue
	CacheDataEncrypted types.BoolValue
	CacheEnabled       types.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type Method struct {
	types.Metadata
	HTTPMethod        types.StringValue
	AuthorizationType types.StringValue
	APIKeyRequired    types.BoolValue
}

type DomainName struct {
	types.Metadata
	Name           types.StringValue
	SecurityPolicy types.StringValue
}
