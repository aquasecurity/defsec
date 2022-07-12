package api_gateway

import (
	"fmt"

	v2 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v2"

	"github.com/aquasecurity/defsec/internal/types"
	api "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	agTypes "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

func (a *adapter) getAPIsV2() ([]v2.API, error) {
	var adapted []v2.API

	a.Tracker().SetServiceLabel("Discovering v2 APIs...")

	var input api.GetApisInput
	var apiApis []agTypes.Api
	for {
		output, err := a.clientV2.GetApis(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiApis = append(apiApis, output.Items...)
		a.Tracker().SetTotalResources(len(apiApis))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting v2 APIs...")

	for _, restAPI := range apiApis {
		adaptedAPI, err := a.adaptAPIV2(restAPI)
		if err != nil {
			return nil, err
		}
		adapted = append(adapted, *adaptedAPI)
		a.Tracker().IncrementResource()
	}

	return adapted, nil
}

func (a *adapter) adaptAPIV2(remoteAPI agTypes.Api) (*v2.API, error) {

	metadata := a.CreateMetadata(fmt.Sprintf("/apis/%s", *remoteAPI.ApiId))

	var stages []v2.Stage
	input := &api.GetStagesInput{
		ApiId: remoteAPI.ApiId,
	}
	for {
		stagesOutput, err := a.clientV2.GetStages(a.Context(), input)
		if err != nil {
			return nil, err
		}
		for _, apiStage := range stagesOutput.Items {
			stages = append(stages, a.adaptStageV2(remoteAPI, apiStage))
		}
		if stagesOutput.NextToken == nil {
			break
		}
		input.NextToken = stagesOutput.NextToken
	}

	return &v2.API{
		Metadata:     metadata,
		Name:         types.String(*remoteAPI.Name, metadata),
		ProtocolType: types.String(string(remoteAPI.ProtocolType), metadata),
		Stages:       stages,
	}, nil
}

func (a *adapter) adaptStageV2(remoteAPI agTypes.Api, stage agTypes.Stage) v2.Stage {
	metadata := a.CreateMetadata(fmt.Sprintf("/apis/%s/stages/%s", *remoteAPI.ApiId, *stage.StageName))

	var logARN string
	if stage.AccessLogSettings.DestinationArn != nil {
		logARN = *stage.AccessLogSettings.DestinationArn
	}

	return v2.Stage{
		Metadata: metadata,
		Name:     types.String(*stage.StageName, metadata),
		AccessLogging: v2.AccessLogging{
			Metadata:              metadata,
			CloudwatchLogGroupARN: types.String(logARN, metadata),
		},
	}
}
