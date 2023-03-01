package frauddetector

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/fsx"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/fsx"
	aatypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
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
	return "fsx"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Fsx.Filesystems, err = a.getFileSystem()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getFileSystem() ([]fsx.Filesystem, error) {
	var apiFileSystem []aatypes.FileSystem
	var input api.DescribeFileSystemsInput

	for {
		output, err := a.api.DescribeFileSystems(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiFileSystem = append(apiFileSystem, output.FileSystems...)

		a.Tracker().SetTotalResources(len(apiFileSystem))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken

	}
	a.Tracker().SetServiceLabel("Adapting fsx...")
	return concurrency.Adapt(apiFileSystem, a.RootAdapter, a.adaptFileSystem), nil

}

func (a *adapter) adaptFileSystem(apiFileSystem aatypes.FileSystem) (*fsx.Filesystem, error) {
	metadata := a.CreateMetadataFromARN(*apiFileSystem.ResourceARN)

	var fst string
	if apiFileSystem.FileSystemType != "" {
		fst = string(apiFileSystem.FileSystemType)
	}

	return &fsx.Filesystem{
		Metadata:       metadata,
		FileSystemType: types.String(fst, metadata),
	}, nil

}
