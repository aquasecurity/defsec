package efs

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/efs"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"
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
	return "efs"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.EFS.FileSystems, err = a.getFilesystems()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getFilesystems() ([]efs.FileSystem, error) {

	a.Tracker().SetServiceLabel("Discovering filesystems...")

	var input api.DescribeFileSystemsInput
	var apiFilesystems []types.FileSystemDescription
	for {
		output, err := a.api.DescribeFileSystems(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiFilesystems = append(apiFilesystems, output.FileSystems...)
		a.Tracker().SetTotalResources(len(apiFilesystems))
		if output.NextMarker == nil {
			break
		}
		input.Marker = output.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting filesystems...")

	var filesystems []efs.FileSystem
	for _, apiFilesystem := range apiFilesystems {
		filesystem, err := a.adaptFilesystem(apiFilesystem)
		if err != nil {
			a.Debug("Failed to adapt filesystem '%s': %s", *apiFilesystem.FileSystemArn, err)
			continue
		}
		filesystems = append(filesystems, *filesystem)
		a.Tracker().IncrementResource()
	}

	return filesystems, nil
}

func (a *adapter) adaptFilesystem(apiFilesystem types.FileSystemDescription) (*efs.FileSystem, error) {
	metadata := a.CreateMetadataFromARN(*apiFilesystem.FileSystemArn)
	return &efs.FileSystem{
		Metadata:  metadata,
		Encrypted: defsecTypes.Bool(*apiFilesystem.Encrypted, metadata),
	}, nil
}
