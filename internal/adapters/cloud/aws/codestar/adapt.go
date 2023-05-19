package codestar

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/codestar"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/codestar"
	types "github.com/aws/aws-sdk-go-v2/service/codestar/types"
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
	return "codestar"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CodeStar.Projects, err = a.getProjects()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getProjects() ([]codestar.Project, error) {

	a.Tracker().SetServiceLabel("Discovering projects...")

	var projects []types.ProjectSummary
	var input api.ListProjectsInput
	for {
		output, err := a.client.ListProjects(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		projects = append(projects, output.Projects...)
		a.Tracker().SetTotalResources(len(projects))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting projects...")
	return concurrency.Adapt(projects, a.RootAdapter, a.adaptProject), nil
}

func (a *adapter) adaptProject(project types.ProjectSummary) (*codestar.Project, error) {
	metadata := a.CreateMetadataFromARN(*project.ProjectArn)

	output, err := a.client.DescribeProject(a.Context(), &api.DescribeProjectInput{
		Id: project.ProjectId,
	})
	if err != nil {
		return nil, err
	}
	return &codestar.Project{
		Metadata:          metadata,
		ProjectTemplateId: defsecTypes.String(*output.ProjectTemplateId, metadata),
	}, nil
}
