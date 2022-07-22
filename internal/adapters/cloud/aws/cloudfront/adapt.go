package cloudfront

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
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
	return "cloudfront"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.client = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Cloudfront.Distributions, err = a.getDistributions()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDistributions() ([]cloudfront.Distribution, error) {

	a.Tracker().SetServiceLabel("Discovering distributions...")

	var apiDistributions []types.DistributionSummary
	var input api.ListDistributionsInput
	for {
		output, err := a.client.ListDistributions(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDistributions = append(apiDistributions, output.DistributionList.Items...)
		a.Tracker().SetTotalResources(len(apiDistributions))
		if output.DistributionList.NextMarker == nil {
			break
		}
		input.Marker = output.DistributionList.NextMarker
	}

	a.Tracker().SetServiceLabel("Adapting distributions...")

	var distributions []cloudfront.Distribution
	for _, apiDistribution := range apiDistributions {
		distribution, err := a.adaptDistribution(apiDistribution)
		if err != nil {
			return nil, err
		}
		distributions = append(distributions, *distribution)
		a.Tracker().IncrementResource()
	}

	return distributions, nil
}

func (a *adapter) adaptDistribution(distribution types.DistributionSummary) (*cloudfront.Distribution, error) {

	metadata := a.CreateMetadataFromARN(*distribution.ARN)

	config, err := a.client.GetDistributionConfig(a.Context(), &api.GetDistributionConfigInput{
		Id: distribution.Id,
	})
	if err != nil {
		return nil, err
	}

	var wafID string
	if distribution.WebACLId != nil {
		wafID = *distribution.WebACLId
	}

	var loggingBucket string
	if config.DistributionConfig.Logging != nil && config.DistributionConfig.Logging.Bucket != nil {
		loggingBucket = *config.DistributionConfig.Logging.Bucket
	}

	var defaultCacheBehaviour string
	if config.DistributionConfig.DefaultCacheBehavior != nil {
		defaultCacheBehaviour = string(config.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy)
	}

	var cacheBehaviours []cloudfront.CacheBehaviour
	for _, cacheBehaviour := range config.DistributionConfig.CacheBehaviors.Items {
		cacheBehaviours = append(cacheBehaviours, cloudfront.CacheBehaviour{
			Metadata:             metadata,
			ViewerProtocolPolicy: defsecTypes.String(string(cacheBehaviour.ViewerProtocolPolicy), metadata),
		})
	}

	var minimumProtocolVersion string
	if config.DistributionConfig.ViewerCertificate != nil {
		minimumProtocolVersion = string(config.DistributionConfig.ViewerCertificate.MinimumProtocolVersion)
	}

	return &cloudfront.Distribution{
		Metadata: metadata,
		WAFID:    defsecTypes.String(wafID, metadata),
		Logging: cloudfront.Logging{
			Metadata: metadata,
			Bucket:   defsecTypes.String(loggingBucket, metadata),
		},
		DefaultCacheBehaviour: cloudfront.CacheBehaviour{
			Metadata:             metadata,
			ViewerProtocolPolicy: defsecTypes.String(defaultCacheBehaviour, metadata),
		},
		OrdererCacheBehaviours: cacheBehaviours,
		ViewerCertificate: cloudfront.ViewerCertificate{
			Metadata:               metadata,
			MinimumProtocolVersion: defsecTypes.String(minimumProtocolVersion, metadata),
		},
	}, nil
}
