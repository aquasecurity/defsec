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
			a.Debug("Failed to adapt trail '%s': %s", *apiDistribution.TrailARN, err)
			continue
		}
		trails = append(trails, *trail)
		a.Tracker().IncrementResource()
	}

	return trails, nil
}

func (a *adapter) adaptTrail(info types.TrailInfo) (*cloudtrail.Trail, error) {

	metadata := a.CreateMetadataFromARN(*info.TrailARN)

	response, err := a.client.GetTrail(a.Context(), &api.GetTrailInput{
		Name: info.TrailARN,
	})
	if err != nil {
		return nil, err
	}

	var kmsKeyId string
	if response.Trail.KmsKeyId != nil {
		kmsKeyId = *response.Trail.KmsKeyId
	}

	status, err := a.client.GetTrailStatus(a.Context(), &api.GetTrailStatusInput{
		Name: response.Trail.Name,
	})
	if err != nil {
		return nil, err
	}

	cloudWatchLogsArn := defsecTypes.StringDefault("", metadata)
	if response.Trail.CloudWatchLogsLogGroupArn != nil {
		cloudWatchLogsArn = defsecTypes.String(*response.Trail.CloudWatchLogsLogGroupArn, metadata)
	}

	var bucketName string
	if response.Trail.S3BucketName != nil {
		bucketName = *response.Trail.S3BucketName
	}

	return &cloudtrail.Trail{
		Metadata:                  metadata,
		Name:                      defsecTypes.String(*info.Name, metadata),
		EnableLogFileValidation:   defsecTypes.Bool(response.Trail.LogFileValidationEnabled != nil && *response.Trail.LogFileValidationEnabled, metadata),
		IsMultiRegion:             defsecTypes.Bool(response.Trail.IsMultiRegionTrail != nil && *response.Trail.IsMultiRegionTrail, metadata),
		CloudWatchLogsLogGroupArn: cloudWatchLogsArn,
		KMSKeyID:                  defsecTypes.String(kmsKeyId, metadata),
		IsLogging:                 defsecTypes.Bool(*status.IsLogging, metadata),
		BucketName:                defsecTypes.String(bucketName, metadata),
	}, nil
}
