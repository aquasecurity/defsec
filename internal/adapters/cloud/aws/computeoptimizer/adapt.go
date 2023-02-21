package computeoptimizer

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/computeoptimizer"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/computeoptimizer"
	types "github.com/aws/aws-sdk-go-v2/service/computeoptimizer/types"
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
	return "computeoptimizer"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ComputeOptimizer.RecommendationSummaries, err = a.getSummaries()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getSummaries() ([]computeoptimizer.RecommendationSummary, error) {

	a.Tracker().SetServiceLabel("Discovering summaries...")

	var summaries []types.RecommendationSummary
	var input api.GetRecommendationSummariesInput
	for {
		output, err := a.client.GetRecommendationSummaries(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, output.RecommendationSummaries...)
		a.Tracker().SetTotalResources(len(summaries))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting summaries...")
	return concurrency.Adapt(summaries, a.RootAdapter, a.adaptProject), nil
}

func (a *adapter) adaptProject(summary types.RecommendationSummary) (*computeoptimizer.RecommendationSummary, error) {
	metadata := a.CreateMetadata(*summary.AccountId)

	var summarylist []computeoptimizer.Summary

	for _, s := range summary.Summaries {
		summarylist = append(summarylist, computeoptimizer.Summary{
			Metadata: metadata,
			Name:     defsecTypes.String(string(s.Name), metadata),
			Value:    defsecTypes.Int(int(s.Value), metadata),
		})
	}

	return &computeoptimizer.RecommendationSummary{
		Metadata:     metadata,
		ResourceType: defsecTypes.String(string(summary.RecommendationResourceType), metadata),
		Summaries:    summarylist,
	}, nil
}
