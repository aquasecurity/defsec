package v1

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

type API struct {
	types2.Metadata
	Name      types2.StringValue
	Stages    []Stage
	Resources []Resource
}

type Stage struct {
	types2.Metadata
	Name               types2.StringValue
	AccessLogging      AccessLogging
	XRayTracingEnabled types2.BoolValue
	RESTMethodSettings []RESTMethodSettings
}

type Resource struct {
	types2.Metadata
	Methods []Method
}

type AccessLogging struct {
	types2.Metadata
	CloudwatchLogGroupARN types2.StringValue
}

type RESTMethodSettings struct {
	types2.Metadata
	Method             types2.StringValue
	CacheDataEncrypted types2.BoolValue
	CacheEnabled       types2.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type Method struct {
	types2.Metadata
	HTTPMethod        types2.StringValue
	AuthorizationType types2.StringValue
	APIKeyRequired    types2.BoolValue
}

type DomainName struct {
	types2.Metadata
	Name           types2.StringValue
	SecurityPolicy types2.StringValue
}
