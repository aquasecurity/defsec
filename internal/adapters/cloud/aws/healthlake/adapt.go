package healthlake

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/healthlake"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/healthlake"
	"github.com/aws/aws-sdk-go-v2/service/healthlake/types"
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
	return "healthlake"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.HealthLake.FHIRDatastores, err = a.getDataStores()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDataStores() ([]healthlake.FHIRDatastore, error) {

	a.Tracker().SetServiceLabel("Discovering datastores...")

	var apidatastores []types.DatastoreProperties
	var input api.ListFHIRDatastoresInput
	for {
		output, err := a.api.ListFHIRDatastores(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apidatastores = append(apidatastores, output.DatastorePropertiesList...)
		a.Tracker().SetTotalResources(len(apidatastores))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting datastores...")
	return concurrency.Adapt(apidatastores, a.RootAdapter, a.adaptJob), nil
}

func (a *adapter) adaptJob(datastore types.DatastoreProperties) (*healthlake.FHIRDatastore, error) {
	metadata := a.CreateMetadataFromARN(*datastore.DatastoreArn)

	var kmskeyid string
	if datastore.SseConfiguration != nil {
		if datastore.SseConfiguration.KmsEncryptionConfig != nil {
			kmskeyid = *datastore.SseConfiguration.KmsEncryptionConfig.KmsKeyId
		}
	}

	return &healthlake.FHIRDatastore{
		Metadata: metadata,
		KmsKeyId: defsecTypes.String(kmskeyid, metadata),
	}, nil
}
