package apigateway

import (
	v2 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v2"
	"github.com/aquasecurity/defsec/pkg/terraform"
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

func adaptAPIsV2(modules terraform.Modules) []v2.API {

	var apis []v2.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_apigatewayv2_stage")

	for _, module := range modules {
		for _, apiBlock := range module.GetResourcesByType("aws_apigatewayv2_api") {
			api := v2.API{
				Metadata:     apiBlock.GetMetadata(),
				Name:         apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock),
				ProtocolType: apiBlock.GetAttribute("protocol_type").AsStringValueOrDefault("", apiBlock),
				Stages:       nil,
			}

			for _, stageBlock := range module.GetReferencingResources(apiBlock, "aws_apigatewayv2_stage", "api_id") {
				apiStageIDs.Resolve(stageBlock.ID())

				stage := adaptStageV2(stageBlock)

				api.Stages = append(api.Stages, stage)
			}

			apis = append(apis, api)
		}
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := v2.API{
			Metadata:     types2.NewUnmanagedMetadata(),
			Name:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
			ProtocolType: types2.StringUnresolvable(types2.NewUnmanagedMetadata()),
			Stages:       nil,
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV2(stage))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV2(stageBlock *terraform.Block) v2.Stage {
	stage := v2.Stage{
		Metadata: stageBlock.GetMetadata(),
		Name:     stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock),
		AccessLogging: v2.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: types2.StringDefault("", stageBlock.GetMetadata()),
		},
	}
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = types2.StringDefault("", stageBlock.GetMetadata())
	}
	return stage
}
