package frauddetector

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/frauddetector"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/frauddetector"
	aatypes "github.com/aws/aws-sdk-go-v2/service/frauddetector/types"
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
	return "frauddetector"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Frauddetector.KmsKey, err = a.getKmsKey()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getKmsKey() (frauddetector.KmsKey, error) {
	var apiKMSKeyArn aatypes.KMSKey
	var input api.GetKMSEncryptionKeyInput

	a.Tracker().SetServiceLabel("Discovering frauddetector kmskey arn...")
	metadata := a.CreateMetadataFromARN(*apiKMSKeyArn.KmsEncryptionKeyArn)

	var kmsArn string
	if apiKMSKeyArn.KmsEncryptionKeyArn != nil {
		kmsArn = *apiKMSKeyArn.KmsEncryptionKeyArn
	}

	description := frauddetector.KmsKey{
		Metadata:            metadata,
		KmsEncryptionKeyArn: defsecTypes.String(kmsArn, metadata),
	}

	output, err := a.api.GetKMSEncryptionKey(a.Context(), &input)
	if err != nil {
		return description, err
	}

	apiKMSKeyArn = *output.KmsKey

	return description, nil
}
