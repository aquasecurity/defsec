package ecr

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	ecrapi "github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/liamg/iamgo"
)

type adapter struct {
	*aws.RootAdapter
	api *ecrapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "ecr"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = ecrapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.ECR.Repositories, err = a.getRepositories()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getRepositories() ([]ecr.Repository, error) {

	a.Tracker().SetServiceLabel("Discovering repositories...")

	var input ecrapi.DescribeRepositoriesInput

	var apiRepositories []types.Repository
	for {
		output, err := a.api.DescribeRepositories(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiRepositories = append(apiRepositories, output.Repositories...)
		a.Tracker().SetTotalResources(len(apiRepositories))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting repositories...")

	var repositories []ecr.Repository
	for _, apiRepository := range apiRepositories {
		repository, err := a.adaptRepository(apiRepository)
		if err != nil {
			a.Debug("Failed to adapt repository '%s': %s", *apiRepository.RepositoryArn, err)
			continue
		}
		repositories = append(repositories, *repository)
		a.Tracker().IncrementResource()
	}

	return repositories, nil
}

func (a *adapter) adaptRepository(apiRepository types.Repository) (*ecr.Repository, error) {

	metadata := a.CreateMetadataFromARN(*apiRepository.RepositoryArn)

	var encType string
	var encKey string
	if apiRepository.EncryptionConfiguration != nil {
		encType = string(apiRepository.EncryptionConfiguration.EncryptionType)
		if apiRepository.EncryptionConfiguration.KmsKey != nil {
			encKey = *apiRepository.EncryptionConfiguration.KmsKey
		}
	}

	immutable := apiRepository.ImageTagMutability == types.ImageTagMutabilityImmutable
	scanOnPush := apiRepository.ImageScanningConfiguration != nil && apiRepository.ImageScanningConfiguration.ScanOnPush

	var policies []iam.Policy

	if output, err := a.api.GetRepositoryPolicy(a.Context(), &ecrapi.GetRepositoryPolicyInput{
		RepositoryName: apiRepository.RepositoryName,
	}); err == nil {
		parsed, err := iamgo.ParseString(*output.PolicyText)
		if err != nil {
			return nil, err
		}
		policies = append(policies, iam.Policy{
			Metadata: metadata,
			Name:     defsecTypes.String(*output.RepositoryName, metadata),
			Document: iam.Document{
				Metadata: metadata,
				Parsed:   *parsed,
			},
			Builtin: defsecTypes.Bool(false, metadata),
		})
	}

	return &ecr.Repository{
		Metadata: metadata,
		ImageScanning: ecr.ImageScanning{
			Metadata:   metadata,
			ScanOnPush: defsecTypes.Bool(scanOnPush, metadata),
		},
		ImageTagsImmutable: defsecTypes.Bool(immutable, metadata),
		Policies:           policies,
		Encryption: ecr.Encryption{
			Metadata: metadata,
			Type:     defsecTypes.String(encType, metadata),
			KMSKeyID: defsecTypes.String(encKey, metadata),
		},
	}, nil
}
