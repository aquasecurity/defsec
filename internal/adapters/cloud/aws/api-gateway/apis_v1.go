package api_gateway

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"

	api "github.com/aws/aws-sdk-go-v2/service/apigateway"
	agTypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

func (a *adapter) getAPIsV1() ([]v1.API, error) {

	a.Tracker().SetServiceLabel("Discovering v1 APIs...")

	var input api.GetRestApisInput
	var apiRestApis []agTypes.RestApi
	for {
		output, err := a.clientV1.GetRestApis(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiRestApis = append(apiRestApis, output.Items...)
		a.Tracker().SetTotalResources(len(apiRestApis))
		if output.Position == nil {
			break
		}
		input.Position = output.Position
	}

	a.Tracker().SetServiceLabel("Adapting v1 APIs...")

	return concurrency.Adapt(apiRestApis, a.RootAdapter, a.adaptRestAPIV1), nil
}

func (a *adapter) adaptRestAPIV1(restAPI agTypes.RestApi) (*v1.API, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("/restapis/%s", *restAPI.Id))

	stagesOutput, err := a.clientV1.GetStages(a.Context(), &api.GetStagesInput{
		RestApiId: restAPI.Id,
	})
	if err != nil {
		return nil, err
	}

	var stages []v1.Stage
	for _, apiStage := range stagesOutput.Item {
		stages = append(stages, a.adaptStageV1(restAPI, apiStage))
	}

	var resources []v1.Resource
	resourcesInput := api.GetResourcesInput{
		RestApiId: restAPI.Id,
		Embed:     []string{"methods"},
		Position:  nil,
	}
	for {
		resourcesOutput, err := a.clientV1.GetResources(a.Context(), &resourcesInput)
		if err != nil {
			return nil, err
		}
		for _, resource := range resourcesOutput.Items {
			resources = append(resources, a.adaptResourceV1(restAPI, resource))
		}
		if resourcesOutput.Position == nil {
			break
		}
		resourcesInput.Position = resourcesOutput.Position
	}

	return &v1.API{
		Metadata:  metadata,
		Name:      defsecTypes.String(*restAPI.Name, metadata),
		Stages:    stages,
		Resources: resources,
	}, nil
}

func (a *adapter) adaptStageV1(restAPI agTypes.RestApi, stage agTypes.Stage) v1.Stage {
	metadata := a.CreateMetadata(fmt.Sprintf("/restapis/%s/stages/%s", *restAPI.Id, *stage.StageName))

	var logARN string
	if stage.AccessLogSettings != nil && stage.AccessLogSettings.DestinationArn != nil {
		logARN = *stage.AccessLogSettings.DestinationArn
	}

	var methodSettings []v1.RESTMethodSettings
	for method, setting := range stage.MethodSettings {
		methodSettings = append(methodSettings, v1.RESTMethodSettings{
			Metadata:           metadata,
			Method:             defsecTypes.String(method, metadata),
			CacheDataEncrypted: defsecTypes.Bool(setting.CacheDataEncrypted, metadata),
			CacheEnabled:       defsecTypes.Bool(setting.CachingEnabled, metadata),
		})
	}

	return v1.Stage{
		Metadata: metadata,
		Name:     defsecTypes.String(*stage.StageName, metadata),
		AccessLogging: v1.AccessLogging{
			Metadata:              metadata,
			CloudwatchLogGroupARN: defsecTypes.String(logARN, metadata),
		},
		RESTMethodSettings: methodSettings,
		XRayTracingEnabled: defsecTypes.Bool(stage.TracingEnabled, metadata),
	}
}

func (a *adapter) adaptResourceV1(restAPI agTypes.RestApi, apiResource agTypes.Resource) v1.Resource {

	metadata := a.CreateMetadata(fmt.Sprintf("/restapis/%s/resources/%s", *restAPI.Id, *apiResource.Id))

	resource := v1.Resource{
		Metadata: metadata,
		Methods:  nil,
	}

	for _, method := range apiResource.ResourceMethods {
		metadata := a.CreateMetadata(fmt.Sprintf("/restapis/%s/resources/%s/methods/%s", *restAPI.Id, *apiResource.Id, *method.HttpMethod))
		resource.Methods = append(resource.Methods, v1.Method{
			Metadata:          metadata,
			HTTPMethod:        defsecTypes.String(*method.HttpMethod, metadata),
			AuthorizationType: defsecTypes.String(*method.AuthorizationType, metadata),
			APIKeyRequired:    defsecTypes.Bool(*method.ApiKeyRequired, metadata),
		})
	}

	return resource
}
