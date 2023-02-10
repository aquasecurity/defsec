package v1

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

type API struct {
	Metadata                  defsecTypes.Metadata
	Name                      defsecTypes.StringValue
	Id                        defsecTypes.StringValue
	MinimumCompressionSize    defsecTypes.IntValue
	EndpointConfiguration     EndpointConfiguration
	Stages                    []Stage
	Resources                 []Resource
	DisableExecuteApiEndpoint defsecTypes.BoolValue
}

type EndpointConfiguration struct {
	Metadata defsecTypes.Metadata
	Types    []defsecTypes.StringValue
}

type Stage struct {
	Metadata            defsecTypes.Metadata
	Name                defsecTypes.StringValue
	ClientCertificateId defsecTypes.StringValue
	ClientCertificate   ClientCertificate
	AccessLogging       AccessLogging
	XRayTracingEnabled  defsecTypes.BoolValue
	RESTMethodSettings  []RESTMethodSettings
	CacheClusterEnabled defsecTypes.BoolValue
	WebAclArn           defsecTypes.StringValue
}

type Resource struct {
	Metadata defsecTypes.Metadata
	Methods  []Method
}

type AccessLogging struct {
	Metadata              defsecTypes.Metadata
	CloudwatchLogGroupARN defsecTypes.StringValue
}

type ClientCertificate struct {
	Metadata       defsecTypes.Metadata
	ExpirationDate defsecTypes.TimeValue
}

type RESTMethodSettings struct {
	Metadata           defsecTypes.Metadata
	Method             defsecTypes.StringValue
	CacheDataEncrypted defsecTypes.BoolValue
	CacheEnabled       defsecTypes.BoolValue
	MetricsEnabled     defsecTypes.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type Method struct {
	Metadata          defsecTypes.Metadata
	HTTPMethod        defsecTypes.StringValue
	AuthorizationType defsecTypes.StringValue
	APIKeyRequired    defsecTypes.BoolValue
}

type DomainName struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	SecurityPolicy defsecTypes.StringValue
}
