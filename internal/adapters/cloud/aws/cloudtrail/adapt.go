package cloudtrail

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
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
	return "cloudtrail"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.CloudTrail.Trails, err = a.getTrails()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getTrails() ([]cloudtrail.Trail, error) {

	a.Tracker().SetServiceLabel("Discovering trails...")

	var apiTrails []types.TrailInfo
	var input api.ListTrailsInput
	for {
		output, err := a.client.ListTrails(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiTrails = append(apiTrails, output.Trails...)
		a.Tracker().SetTotalResources(len(apiTrails))
		if output.NextToken == nil {
			break
		}
		input.NextToken = output.NextToken
	}

	a.Tracker().SetServiceLabel("Adapting trails...")

	var trails []cloudtrail.Trail
	for _, apiDistribution := range apiTrails {
		trail, err := a.adaptTrail(apiDistribution)
		if err != nil {
			return nil, err
		}
		trails = append(trails, *trail)
		a.Tracker().IncrementResource()
	}

	return trails, nil
}

func (a *adapter) adaptTrail(info types.TrailInfo) (*cloudtrail.Trail, error) {

	metadata := a.CreateMetadataFromARN(*info.TrailARN)

	trail, err := a.client.GetTrail(a.Context(), &api.GetTrailInput{
		Name: info.Name,
	})
	if err != nil {
		return nil, err
	}

	var kmsKeyId string
	if trail.Trail.KmsKeyId != nil {
		kmsKeyId = *trail.Trail.KmsKeyId
	}

	return &cloudtrail.Trail{
		Metadata:                metadata,
		Name:                    defsecTypes.String(*info.Name, metadata),
		EnableLogFileValidation: defsecTypes.Bool(trail.Trail.LogFileValidationEnabled != nil && *trail.Trail.LogFileValidationEnabled, metadata),
		IsMultiRegion:           defsecTypes.Bool(trail.Trail.IsMultiRegionTrail != nil && *trail.Trail.IsMultiRegionTrail, metadata),
		KMSKeyID:                defsecTypes.String(kmsKeyId, metadata),
	}, nil
}
