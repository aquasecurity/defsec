package api_gateway

import (
	"fmt"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/accessanalyzer"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	api "github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
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
	return "accessanalyzer"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())

	var err error
	state.AWS.AccessAnalyzer.Analyzers, err = a.adaptAnalyzers()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) adaptAnalyzers() ([]accessanalyzer.Analyzer, error) {
	a.Tracker().SetServiceLabel("Discovering analyzers...")

	var input api.ListAnalyzersInput
	var apiAnalyzers []aatypes.AnalyzerSummary
	for {
		output, err := a.api.ListAnalyzers(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiAnalyzers = append(apiAnalyzers, output.Analyzers...)
		a.Tracker().SetTotalResources(len(apiAnalyzers))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting analyzers...")
	return concurrency.Adapt(apiAnalyzers, a.RootAdapter, a.adaptAnalyzer), nil
}

func (a *adapter) adaptAnalyzer(apiAnalyzer aatypes.AnalyzerSummary) (*accessanalyzer.Analyzer, error) {

	if apiAnalyzer.Arn == nil {
		return nil, fmt.Errorf("missing arn")
	}
	parsed, err := arn.Parse(*apiAnalyzer.Arn)
	if err != nil {
		return nil, fmt.Errorf("invalid arn: %w", err)
	}
	if parsed.Region != a.Region() {
		return nil, nil // skip other regions
	}

	metadata := a.CreateMetadataFromARN(*apiAnalyzer.Arn)
	var name string
	if apiAnalyzer.Name != nil {
		name = *apiAnalyzer.Name
	}

	var findings []accessanalyzer.Findings
	output, err := a.api.ListFindings(a.Context(), &api.ListFindingsInput{
		AnalyzerArn: apiAnalyzer.Arn,
	})
	if err != nil {
		return nil, err
	}
	if output.Findings != nil {
		for _, r := range output.Findings {
			findings = append(findings, accessanalyzer.Findings{
				Metadata: metadata,
			})
			_ = r
		}
	}

	return &accessanalyzer.Analyzer{
		Metadata: metadata,
		ARN:      types.String(*apiAnalyzer.Arn, metadata),
		Name:     types.String(name, metadata),
		Active:   types.Bool(apiAnalyzer.Status == aatypes.AnalyzerStatusActive, metadata),
		Findings: findings,
	}, nil
}
