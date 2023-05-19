package connect

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/connect"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/connect"
	types "github.com/aws/aws-sdk-go-v2/service/connect/types"
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
	return "connect"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Connect.Instances, err = a.getInstances()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getInstances() ([]connect.Instance, error) {

	a.Tracker().SetServiceLabel("Discovering instances...")

	var instances []types.InstanceSummary
	var input api.ListInstancesInput
	for {
		output, err := a.client.ListInstances(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		instances = append(instances, output.InstanceSummaryList...)
		a.Tracker().SetTotalResources(len(instances))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting connects...")
	return concurrency.Adapt(instances, a.RootAdapter, a.adaptInstance), nil
}

func (a *adapter) adaptInstance(instance types.InstanceSummary) (*connect.Instance, error) {

	metadata := a.CreateMetadataFromARN(*instance.Arn)

	return &connect.Instance{
		Metadata:                      metadata,
		AttachmentStorageconfigs:      a.getstorageconfig(instance, connect.ResourceType[0], metadata),
		CallRecordingStorageconfigs:   a.getstorageconfig(instance, connect.ResourceType[1], metadata),
		ChatTranscriptsStorageconfigs: a.getstorageconfig(instance, connect.ResourceType[2], metadata),
		ExportedReportStorageconfigs:  a.getstorageconfig(instance, connect.ResourceType[3], metadata),
		MediaStreamsStorageconfigs:    a.getstorageconfig(instance, connect.ResourceType[4], metadata),
	}, nil
}

func (a *adapter) getstorageconfig(instance types.InstanceSummary, resource types.InstanceStorageResourceType, metadata defsecTypes.Metadata) []connect.StorageConfig {
	var storageconfig []connect.StorageConfig
	output, err := a.client.ListInstanceStorageConfigs(a.Context(), &api.ListInstanceStorageConfigsInput{
		InstanceId:   instance.Id,
		ResourceType: resource,
	})
	if err != nil {
		return storageconfig
	}
	for _, sc := range output.StorageConfigs {

		var key string
		if resource == "MEDIA_STREAMS" {
			if sc.KinesisVideoStreamConfig != nil && sc.KinesisVideoStreamConfig.EncryptionConfig != nil {
				key = *sc.KinesisVideoStreamConfig.EncryptionConfig.KeyId
			}
		} else {
			if sc.S3Config != nil && sc.S3Config.EncryptionConfig != nil {
				key = *sc.S3Config.EncryptionConfig.KeyId
			}
		}
		storageconfig = append(storageconfig, connect.StorageConfig{
			Metadata: metadata,
			KmsKeyId: defsecTypes.String(key, metadata),
		})
	}
	return storageconfig
}
