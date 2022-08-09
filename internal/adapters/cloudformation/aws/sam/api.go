package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func getApis(cfFile parser.FileContext) (apis []sam.API) {

	apiResources := cfFile.GetResourcesByType("AWS::Serverless::Api")
	for _, r := range apiResources {
		api := sam.API{
			Metadata:            r.Metadata(),
			Name:                r.GetStringProperty("Name", ""),
			TracingEnabled:      r.GetBoolProperty("TracingEnabled"),
			DomainConfiguration: getDomainConfiguration(r),
			AccessLogging:       getAccessLogging(r),
			RESTMethodSettings:  getRestMethodSettings(r),
		}

		apis = append(apis, api)
	}

	return apis
}

func getRestMethodSettings(r *parser.Resource) sam.RESTMethodSettings {

	settings := sam.RESTMethodSettings{
		Metadata:           r.Metadata(),
		CacheDataEncrypted: types2.BoolDefault(false, r.Metadata()),
		LoggingEnabled:     types2.BoolDefault(false, r.Metadata()),
		DataTraceEnabled:   types2.BoolDefault(false, r.Metadata()),
		MetricsEnabled:     types2.BoolDefault(false, r.Metadata()),
	}

	settingsProp := r.GetProperty("MethodSettings")
	if settingsProp.IsNotNil() {

		settings = sam.RESTMethodSettings{
			Metadata:           settingsProp.Metadata(),
			CacheDataEncrypted: settingsProp.GetBoolProperty("CacheDataEncrypted"),
			LoggingEnabled:     types2.BoolDefault(false, settingsProp.Metadata()),
			DataTraceEnabled:   settingsProp.GetBoolProperty("DataTraceEnabled"),
			MetricsEnabled:     settingsProp.GetBoolProperty("MetricsEnabled"),
		}

		if loggingLevel := settingsProp.GetProperty("LoggingLevel"); loggingLevel.IsNotNil() {
			if loggingLevel.EqualTo("OFF", parser.IgnoreCase) {
				settings.LoggingEnabled = types2.Bool(false, loggingLevel.Metadata())
			} else {
				settings.LoggingEnabled = types2.Bool(true, loggingLevel.Metadata())
			}
		}
	}

	return settings
}

func getAccessLogging(r *parser.Resource) sam.AccessLogging {

	logging := sam.AccessLogging{
		Metadata:              r.Metadata(),
		CloudwatchLogGroupARN: types2.StringDefault("", r.Metadata()),
	}

	if access := r.GetProperty("AccessLogSetting"); access.IsNotNil() {
		logging = sam.AccessLogging{
			Metadata:              access.Metadata(),
			CloudwatchLogGroupARN: access.GetStringProperty("DestinationArn", ""),
		}
	}

	return logging
}

func getDomainConfiguration(r *parser.Resource) sam.DomainConfiguration {

	domainConfig := sam.DomainConfiguration{
		Metadata:       r.Metadata(),
		Name:           types2.StringDefault("", r.Metadata()),
		SecurityPolicy: types2.StringDefault("TLS_1_0", r.Metadata()),
	}

	if domain := r.GetProperty("Domain"); domain.IsNotNil() {
		domainConfig = sam.DomainConfiguration{
			Metadata:       domain.Metadata(),
			Name:           domain.GetStringProperty("DomainName", ""),
			SecurityPolicy: domain.GetStringProperty("SecurityPolicy", "TLS_1_0"),
		}
	}

	return domainConfig

}
