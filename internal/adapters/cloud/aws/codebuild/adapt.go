package codebuild

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/codebuild"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/codebuild"
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
	return "codebuild"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CodeBuild.Projects, err = a.getProjects()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getProjects() ([]codebuild.Project, error) {

	a.Tracker().SetServiceLabel("Discovering projects...")

	var projectNames []string
	var input api.ListProjectsInput
	for {
		output, err := a.client.ListProjects(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		projectNames = append(projectNames, output.Projects...)
		a.Tracker().SetTotalResources(len(projectNames))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting projects...")
	return concurrency.Adapt(projectNames, a.RootAdapter, a.adaptProject), nil
}

func (a *adapter) adaptProject(name string) (*codebuild.Project, error) {

	output, err := a.client.BatchGetProjects(a.Context(), &api.BatchGetProjectsInput{
		Names: []string{name},
	})
	if err != nil {
		return nil, err
	}

	project := output.Projects[0]

	metadata := a.CreateMetadataFromARN(*project.Arn)

	encryptionEnabled := true
	if project.Artifacts != nil {
		if project.Artifacts.EncryptionDisabled != nil {
			encryptionEnabled = !*project.Artifacts.EncryptionDisabled
		}
	}

	var secondaryArtifactSettings []codebuild.ArtifactSettings
	for _, settings := range project.SecondaryArtifacts {
		encryptionEnabled := true
		if settings.EncryptionDisabled != nil {
			encryptionEnabled = !*settings.EncryptionDisabled
		}
		secondaryArtifactSettings = append(secondaryArtifactSettings, codebuild.ArtifactSettings{
			Metadata:          metadata,
			EncryptionEnabled: defsecTypes.Bool(encryptionEnabled, metadata),
		})
	}

	var encryptionkey, sourcetype string
	if project.EncryptionKey != nil {
		encryptionkey = *project.EncryptionKey
	}

	if project.Source != nil {
		sourcetype = string(project.Source.Type)
	}

	var secondrysources []codebuild.SecondarySources
	for _, s := range project.SecondarySources {
		secondrysources = append(secondrysources, codebuild.SecondarySources{
			Metadata: metadata,
			Type:     defsecTypes.String(string(s.Type), metadata),
		})
	}

	return &codebuild.Project{
		Metadata:      metadata,
		SourceType:    defsecTypes.String(sourcetype, metadata),
		EncryptionKey: defsecTypes.String(encryptionkey, metadata),
		ArtifactSettings: codebuild.ArtifactSettings{
			Metadata:          metadata,
			EncryptionEnabled: defsecTypes.Bool(encryptionEnabled, metadata),
		},
		SecondaryArtifactSettings: secondaryArtifactSettings,
		SecondarySources:          secondrysources,
	}, nil
}
