package apigateway

import (
	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getApisV1(cfFile parser.FileContext) (apis []v1.API) {

	apiResources := cfFile.GetResourcesByType("AWS::ApiGateway::RestApi")
	for _, apiRes := range apiResources {
		api := v1.API{
			Metadata:                  apiRes.Metadata(),
			Name:                      apiRes.GetStringProperty("Name"),
			Id:                        apiRes.GetStringProperty("RestApiId"),
			MinimumCompressionSize:    apiRes.GetIntProperty("MinimumCompressionSize"),
			DisableExecuteApiEndpoint: apiRes.GetBoolProperty("DisableExecuteApiEndpoint"),
			EndpointConfiguration:     getEndPointConfiguration(apiRes),
			Stages:                    getStagesV1(apiRes.ID(), cfFile),
			Resources:                 nil,
		}
		apis = append(apis, api)
	}

	return apis
}

func getDomain(cfFile parser.FileContext) (domains []v1.DomainName) {

	domainRes := cfFile.GetResourcesByType("")
	for _, r := range domainRes {
		domain := v1.DomainName{
			Metadata:       r.Metadata(),
			Name:           r.GetStringProperty("DomainName"),
			SecurityPolicy: r.GetStringProperty("SecurityPolicy"),
		}
		domains = append(domains, domain)
	}
	return domains
}

func getStagesV1(apiId string, cfFile parser.FileContext) []v1.Stage {
	var apiStages []v1.Stage

	stageResources := cfFile.GetResourcesByType("AWS::ApiGateway::Stage")
	for _, r := range stageResources {
		stageApiId := r.GetStringProperty("ApiId")
		if stageApiId.Value() != apiId {
			continue
		}

		s := v1.Stage{
			Metadata:            r.Metadata(),
			Name:                r.GetStringProperty("StageName"),
			ClientCertificateId: r.GetStringProperty("ClientCertificateId"),
			ClientCertificate: v1.ClientCertificate{
				Metadata:       r.Metadata(),
				ExpirationDate: types.TimeUnresolvable(r.Metadata()),
			},
			XRayTracingEnabled:  r.GetBoolProperty("TracingEnabled"),
			CacheClusterEnabled: r.GetBoolProperty("CacheClusterEnabled"),
			WebAclArn:           types.String("", r.Metadata()),
			AccessLogging:       getAccessLoggingV1(r),
			RESTMethodSettings:  getRestMethodSettings(r),
		}
		apiStages = append(apiStages, s)
	}

	return apiStages
}

func getAccessLoggingV1(r *parser.Resource) v1.AccessLogging {

	loggingProp := r.GetProperty("AccessLogSetting")
	if loggingProp.IsNil() {
		return v1.AccessLogging{
			Metadata:              r.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}

	destinationProp := r.GetProperty("AccessLogSetting.DestinationArn")

	if destinationProp.IsNil() {
		return v1.AccessLogging{
			Metadata:              loggingProp.Metadata(),
			CloudwatchLogGroupARN: types.StringDefault("", r.Metadata()),
		}
	}
	return v1.AccessLogging{
		Metadata:              destinationProp.Metadata(),
		CloudwatchLogGroupARN: destinationProp.AsStringValue(),
	}
}

func getRestMethodSettings(r *parser.Resource) []v1.RESTMethodSettings {
	settingProp := r.GetProperty("MethodSetting")
	var settings []v1.RESTMethodSettings
	if settingProp.IsNil() || settingProp.IsNotList() {
		return settings
	}

	for _, s := range settingProp.AsList() {
		settings = append(settings, v1.RESTMethodSettings{
			Metadata:           s.Metadata(),
			CacheDataEncrypted: r.GetBoolProperty("CacheDataEncrypted"),
			CacheEnabled:       r.GetBoolProperty("CachingEnabled"),
			MetricsEnabled:     r.GetBoolProperty("MetricsEnabled"),
		})
	}
	return settings
}

func getEndPointConfiguration(r *parser.Resource) v1.EndpointConfiguration {
	var EPC v1.EndpointConfiguration
	if EPCProp := r.GetProperty("EndpointConfiguration"); EPCProp.IsNotNil() {
		var types []types.StringValue
		typesprop := EPCProp.GetProperty("Types")
		if typesprop.IsNil() || typesprop.IsNotList() {
			types = nil
		}
		for _, t := range typesprop.AsList() {
			types = append(types, t.AsStringValue())
		}
		EPC = v1.EndpointConfiguration{
			Metadata: EPC.Metadata,
			Types:    types,
		}

	}
	return EPC
}
