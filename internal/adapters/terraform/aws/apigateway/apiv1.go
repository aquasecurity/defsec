package apigateway

import (
	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"
	"github.com/aquasecurity/defsec/pkg/terraform"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func adaptAPIResourcesV1(modules terraform.Modules, apiBlock *terraform.Block) []v1.Resource {
	var resources []v1.Resource
	for _, resourceBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_resource", "rest_api_id") {
		method := v1.Resource{
			Metadata: resourceBlock.GetMetadata(),
			Methods:  adaptAPIMethodsV1(modules, resourceBlock),
		}
		resources = append(resources, method)
	}
	return resources
}

func adaptAPIMethodsV1(modules terraform.Modules, resourceBlock *terraform.Block) []v1.Method {
	var methods []v1.Method
	for _, methodBlock := range modules.GetReferencingResources(resourceBlock, "aws_api_gateway_method", "resource_id") {
		method := v1.Method{
			Metadata:          methodBlock.GetMetadata(),
			HTTPMethod:        methodBlock.GetAttribute("http_method").AsStringValueOrDefault("", methodBlock),
			AuthorizationType: methodBlock.GetAttribute("authorization").AsStringValueOrDefault("", methodBlock),
			APIKeyRequired:    methodBlock.GetAttribute("api_key_required").AsBoolValueOrDefault(false, methodBlock),
		}
		methods = append(methods, method)
	}
	return methods
}

func adaptAPIsV1(modules terraform.Modules) []v1.API {

	var apis []v1.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_api_gateway_stage")

	for _, apiBlock := range modules.GetResourcesByType("aws_api_gateway_rest_api") {

		var types []defsecTypes.StringValue
		for _, t := range apiBlock.GetBlocks("endpoint_configuration") {
			typeAttr := t.GetAttribute("types").AsStringValueOrDefault("", t)
			types = append(types, typeAttr)
		}
		api := v1.API{
			Metadata:               apiBlock.GetMetadata(),
			Name:                   apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock),
			Id:                     apiBlock.GetAttribute("id").AsStringValueOrDefault("", apiBlock),
			MinimumCompressionSize: apiBlock.GetAttribute("minimum_compression_size").AsIntValueOrDefault(-1, apiBlock),
			Stages:                 nil,
			EndpointConfiguration: v1.EndpointConfiguration{
				Metadata: apiBlock.GetMetadata(),
				Types:    types,
			},
			Resources:                 adaptAPIResourcesV1(modules, apiBlock),
			DisableExecuteApiEndpoint: apiBlock.GetAttribute("disable_execute_api_endpoint").AsBoolValueOrDefault(false, apiBlock),
		}

		for _, stageBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_stage", "rest_api_id") {
			apiStageIDs.Resolve(stageBlock.ID())
			stage := adaptStageV1(stageBlock, modules)

			api.Stages = append(api.Stages, stage)
		}

		apis = append(apis, api)
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := v1.API{
			Metadata: defsecTypes.NewUnmanagedMetadata(),
			Name:     defsecTypes.StringDefault("", defsecTypes.NewUnmanagedMetadata()),
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV1(stage, modules))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV1(stageBlock *terraform.Block, modules terraform.Modules) v1.Stage {
	stage := v1.Stage{
		Metadata:            stageBlock.GetMetadata(),
		Name:                stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock),
		ClientCertificateId: stageBlock.GetAttribute("client_certificate_id").AsStringValueOrDefault("", stageBlock),
		AccessLogging: v1.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: defsecTypes.StringDefault("", stageBlock.GetMetadata()),
		},
		XRayTracingEnabled:  stageBlock.GetAttribute("xray_tracing_enabled").AsBoolValueOrDefault(false, stageBlock),
		CacheClusterEnabled: stageBlock.GetAttribute("cache_cluster_enabled").AsBoolValueOrDefault(false, stageBlock),
		WebAclArn:           defsecTypes.StringDefault("", stageBlock.GetMetadata()),
	}

	for _, C := range modules.GetReferencingResources(stageBlock, "aws_api_gateway_client_certificate", "id") {
		clientCertificate := v1.ClientCertificate{
			Metadata:       C.GetMetadata(),
			ExpirationDate: defsecTypes.TimeUnresolvable(C.GetMetadata()),
		}
		stage.ClientCertificate = clientCertificate
	}
	for _, methodSettings := range modules.GetReferencingResources(stageBlock, "aws_api_gateway_method_settings", "stage_name") {

		restMethodSettings := v1.RESTMethodSettings{
			Metadata:           methodSettings.GetMetadata(),
			Method:             defsecTypes.String("", methodSettings.GetMetadata()),
			CacheDataEncrypted: defsecTypes.BoolDefault(false, methodSettings.GetMetadata()),
			CacheEnabled:       defsecTypes.BoolDefault(false, methodSettings.GetMetadata()),
			MetricsEnabled:     defsecTypes.BoolDefault(false, methodSettings.GetMetadata()),
		}

		if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
			if encrypted := settings.GetAttribute("cache_data_encrypted"); encrypted.IsNotNil() {
				restMethodSettings.CacheDataEncrypted = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
			}
			if encrypted := settings.GetAttribute("caching_enabled"); encrypted.IsNotNil() {
				restMethodSettings.CacheEnabled = settings.GetAttribute("caching_enabled").AsBoolValueOrDefault(false, settings)
			}
			if encrypted := settings.GetAttribute("metrics_enabled"); encrypted.IsNotNil() {
				restMethodSettings.MetricsEnabled = settings.GetAttribute("metrics_enabled").AsBoolValueOrDefault(false, settings)
			}

		}

		stage.RESTMethodSettings = append(stage.RESTMethodSettings, restMethodSettings)
	}

	stage.Name = stageBlock.GetAttribute("stage_name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = defsecTypes.StringDefault("", stageBlock.GetMetadata())
	}
	stage.WebAclArn = stageBlock.GetAttribute("web_acl_arn").AsStringValueOrDefault("", stageBlock)
	return stage
}
