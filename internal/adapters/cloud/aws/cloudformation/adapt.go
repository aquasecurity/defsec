package cloudformation

import (
	"github.com/aquasecurity/defsec/pkg/concurrency"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudformation"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

type adapter struct {
	*aws.RootAdapter
	client *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "cloudformation"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Cloudformation.Stacks, err = a.getStacks()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getStacks() ([]cloudformation.Stack, error) {

	a.Tracker().SetServiceLabel("Discovering stacks...")

	var apistacks []types.StackSummary
	var input api.ListStacksInput
	for {
		output, err := a.client.ListStacks(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apistacks = append(apistacks, output.StackSummaries...)
		a.Tracker().SetTotalResources(len(apistacks))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting stacks...")
	return concurrency.Adapt(apistacks, a.RootAdapter, a.adaptStack), nil
}

func (a *adapter) adaptStack(apistack types.StackSummary) (*cloudformation.Stack, error) {
	metadata := a.CreateMetadata(*apistack.StackName)

	stack, err := a.client.DescribeStacks(a.Context(), &api.DescribeStacksInput{
		StackName: apistack.StackName,
	})
	if err != nil {
		return nil, err
	}

	var stackstatus, RoleArn string
	var terprovider bool
	var parameters []cloudformation.Parameter
	var notarns []defsecTypes.StringValue
	for _, s := range stack.Stacks {

		stackstatus = string(s.StackStatus)

		if s.RoleARN != nil {
			RoleArn = *s.RoleARN
		}

		terprovider = *s.EnableTerminationProtection

		for _, p := range s.Parameters {
			parameters = append(parameters, cloudformation.Parameter{
				Metadata:     metadata,
				ParameterKey: defsecTypes.String(*p.ParameterKey, metadata),
			})
		}

		for _, noti := range s.NotificationARNs {
			notarns = append(notarns, defsecTypes.String(noti, metadata))
		}
	}

	var events []cloudformation.StackEvent
	event, err := a.client.DescribeStackEvents(a.Context(), &api.DescribeStackEventsInput{
		StackName: apistack.StackName,
	})
	if err != nil {
		event = nil
	}
	if event != nil {
		for _, e := range event.StackEvents {
			events = append(events, cloudformation.StackEvent{
				Metadata:  metadata,
				Timestamp: defsecTypes.Time(*e.Timestamp, metadata),
			})
		}
	}

	var driftstatus string
	if apistack.DriftInformation != nil {
		driftstatus = string(apistack.DriftInformation.StackDriftStatus)
	}

	return &cloudformation.Stack{
		Metadata:                    metadata,
		StackId:                     defsecTypes.String(*apistack.StackId, metadata),
		StackName:                   defsecTypes.String(*apistack.StackName, metadata),
		StackStatus:                 defsecTypes.String(stackstatus, metadata),
		EnableTerminationProtection: defsecTypes.Bool(terprovider, metadata),
		RoleArn:                     defsecTypes.String(RoleArn, metadata),
		StackDriftStatus:            defsecTypes.String(driftstatus, metadata),
		NotificationARNs:            notarns,
		Parameters:                  parameters,
		StackEvents:                 events,
	}, nil
}
