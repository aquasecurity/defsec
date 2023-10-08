package config

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/configservice"
	types "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

type adapter struct {
	*aws.RootAdapter
	Client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "config"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.Client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Config.Rules, err = a.getRules()
	if err != nil {
		return err
	}

	state.AWS.Config.RecorderStatus, err = a.getRecorderStatus()
	if err != nil {
		return err
	}

	state.AWS.Config.Recorders, err = a.getRecorders()
	if err != nil {
		return err
	}

	state.AWS.Config.DeliveryChannels, err = a.getDeliveryChannels()
	if err != nil {
		return err
	}

	state.AWS.Config.ResourceCounts, err = a.getResourceCount()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getRules() ([]config.Rule, error) {

	a.Tracker().SetServiceLabel("Discovering config rules...")
	var apiconfig []types.ConfigRule

	var input api.DescribeConfigRulesInput
	for {
		output, err := a.Client.DescribeConfigRules(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiconfig = append(apiconfig, output.ConfigRules...)
		a.Tracker().SetTotalResources(len(apiconfig))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting config rules...")
	return concurrency.Adapt(apiconfig, a.RootAdapter, a.adaptRule), nil
}

func (a *adapter) adaptRule(rule types.ConfigRule) (*config.Rule, error) {

	metadata := a.CreateMetadataFromARN(*rule.ConfigRuleArn)

	var results []config.EvaluateResult
	output, err := a.Client.GetComplianceDetailsByConfigRule(a.Context(), &api.GetComplianceDetailsByConfigRuleInput{
		ConfigRuleName: rule.ConfigRuleName,
	})
	if err != nil {
		return nil, err
	}

	for range output.EvaluationResults {
		results = append(results, config.EvaluateResult{
			Metadata: metadata,
		})
	}

	return &config.Rule{
		Metadata:        metadata,
		Arn:             defsecTypes.String(*rule.ConfigRuleArn, metadata),
		EvaluateResults: results,
	}, nil
}

func (a *adapter) getRecorders() ([]config.Recorder, error) {

	a.Tracker().SetServiceLabel("Discovering config recorders...")
	var apiconfig []types.ConfigurationRecorder

	var input api.DescribeConfigurationRecordersInput
	for {
		output, err := a.Client.DescribeConfigurationRecorders(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiconfig = append(apiconfig, output.ConfigurationRecorders...)
		a.Tracker().SetTotalResources(len(apiconfig))
		if output.ConfigurationRecorders == nil {
			break
		}
	}

	a.Tracker().SetServiceLabel("Adapting config recorders...")
	return concurrency.Adapt(apiconfig, a.RootAdapter, a.adaptRecorder), nil
}

func (a *adapter) adaptRecorder(recorder types.ConfigurationRecorder) (*config.Recorder, error) {

	var RT bool
	if recorder.RecordingGroup != nil {
		RT = recorder.RecordingGroup.IncludeGlobalResourceTypes
	}

	metadata := a.CreateMetadata(*recorder.Name)
	return &config.Recorder{
		Metadata:                   metadata,
		IncludeGlobalResourceTypes: defsecTypes.Bool(RT, metadata),
	}, nil
}

func (a *adapter) getRecorderStatus() ([]config.RecorderStatus, error) {

	a.Tracker().SetServiceLabel("Discovering config recorder status...")
	var apiconfig []types.ConfigurationRecorderStatus

	var input api.DescribeConfigurationRecorderStatusInput
	for {
		output, err := a.Client.DescribeConfigurationRecorderStatus(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiconfig = append(apiconfig, output.ConfigurationRecordersStatus...)
		a.Tracker().SetTotalResources(len(apiconfig))
		if output.ConfigurationRecordersStatus == nil {
			break
		}
	}

	a.Tracker().SetServiceLabel("Adapting config recorder status...")
	return concurrency.Adapt(apiconfig, a.RootAdapter, a.adaptRecorderStatus), nil
}

func (a *adapter) adaptRecorderStatus(recorder types.ConfigurationRecorderStatus) (*config.RecorderStatus, error) {

	metadata := a.CreateMetadata(*recorder.Name)
	return &config.RecorderStatus{
		Metadata:   metadata,
		LastStatus: defsecTypes.String(string(recorder.LastStatus), metadata),
		Recording:  defsecTypes.Bool(recorder.Recording, metadata),
	}, nil
}

func (a *adapter) getResourceCount() ([]config.ResourceCount, error) {

	a.Tracker().SetServiceLabel("Discovering config resource count...")
	var apiresourcecount []types.ResourceCount

	var input api.GetDiscoveredResourceCountsInput
	for {
		output, err := a.Client.GetDiscoveredResourceCounts(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiresourcecount = append(apiresourcecount, output.ResourceCounts...)
		a.Tracker().SetTotalResources(len(apiresourcecount))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting config resource count...")
	return concurrency.Adapt(apiresourcecount, a.RootAdapter, a.adaptResourceCount), nil
}

func (a *adapter) adaptResourceCount(resource types.ResourceCount) (*config.ResourceCount, error) {

	metadata := a.CreateMetadata(string(resource.ResourceType))
	return &config.ResourceCount{
		Metadata:     metadata,
		ResourceType: defsecTypes.String(string(resource.ResourceType), metadata),
	}, nil
}

func (a *adapter) getDeliveryChannels() ([]config.DeliveryChannel, error) {

	a.Tracker().SetServiceLabel("Discovering delivery channels...")
	var apichannel []types.DeliveryChannel

	var input api.DescribeDeliveryChannelsInput
	for {
		output, err := a.Client.DescribeDeliveryChannels(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apichannel = append(apichannel, output.DeliveryChannels...)
		a.Tracker().SetTotalResources(len(apichannel))
		if output.DeliveryChannels == nil {
			break
		}
	}

	a.Tracker().SetServiceLabel("Adapting delivery channels...")
	return concurrency.Adapt(apichannel, a.RootAdapter, a.adaptDeliveryChannel), nil
}

func (a *adapter) adaptDeliveryChannel(channel types.DeliveryChannel) (*config.DeliveryChannel, error) {

	metadata := a.CreateMetadata(*channel.Name)
	return &config.DeliveryChannel{
		Metadata:   metadata,
		BucketName: defsecTypes.String(*channel.S3BucketName, metadata),
	}, nil
}
