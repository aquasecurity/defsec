package eventbridge

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/eventbridge"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "eventbridge"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EventBridge.Buses, err = a.getBuses()
	if err != nil {
		return err
	}

	state.AWS.EventBridge.Rules, err = a.getRules()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getBuses() ([]eventbridge.Bus, error) {

	a.Tracker().SetServiceLabel("Discovering buses..")

	var input api.ListEventBusesInput

	var apiBuses []types.EventBus
	for {
		output, err := a.api.ListEventBuses(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiBuses = append(apiBuses, output.EventBuses...)
		a.Tracker().SetTotalResources(len(apiBuses))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting buses..")
	return concurrency.Adapt(apiBuses, a.RootAdapter, a.adaptBus), nil
}

func (a *adapter) adaptBus(bus types.EventBus) (*eventbridge.Bus, error) {
	metadata := a.CreateMetadataFromARN(*bus.Arn)

	return &eventbridge.Bus{
		Metadata: metadata,
		Policy:   defsecTypes.String(*bus.Policy, metadata),
	}, nil
}

func (a *adapter) getRules() ([]eventbridge.Rule, error) {

	a.Tracker().SetServiceLabel("Discovering rules..")

	var input api.ListRulesInput

	var apiRules []types.Rule
	for {
		output, err := a.api.ListRules(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiRules = append(apiRules, output.Rules...)
		a.Tracker().SetTotalResources(len(apiRules))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting rules..")
	return concurrency.Adapt(apiRules, a.RootAdapter, a.adaptRule), nil
}

func (a *adapter) adaptRule(rule types.Rule) (*eventbridge.Rule, error) {
	metadata := a.CreateMetadataFromARN(*rule.Arn)

	return &eventbridge.Rule{
		Metadata: metadata,
	}, nil
}
