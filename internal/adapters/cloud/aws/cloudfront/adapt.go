package cloudfront

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
	return concurrency.Adapt(apiDistributions, a.RootAdapter, a.adaptDistribution), nil
}

func (a *adapter) adaptDistribution(distribution types.DistributionSummary) (*cloudfront.Distribution, error) {

	metadata := a.CreateMetadataFromARN(*distribution.ARN)

	config, err := a.client.GetDistributionConfig(a.Context(), &api.GetDistributionConfigInput{
		Id: distribution.Id,
	})
	if err != nil {
		return nil, err
	}

	output, err := a.client.GetDistribution(a.Context(), &api.GetDistributionInput{
		Id: distribution.Id,
	})
	if err != nil {
		output = nil
	}
	var etag string
	var loggingenabled bool
	if output != nil {
		etag = *output.ETag
		if output.Distribution.DistributionConfig != nil {
			loggingenabled = *output.Distribution.DistributionConfig.Logging.Enabled
		}
	}

	var wafID string
	if distribution.WebACLId != nil {
		wafID = *distribution.WebACLId
	}

	var loggingBucket string
	if config.DistributionConfig.Logging != nil && config.DistributionConfig.Logging.Bucket != nil {
		loggingBucket = *config.DistributionConfig.Logging.Bucket
	}

	var viewerProtocolPolicy, fieldLevelEncryptionId string
	var compress bool
	if distribution.DefaultCacheBehavior != nil {
		viewerProtocolPolicy = string(distribution.DefaultCacheBehavior.ViewerProtocolPolicy)
		fieldLevelEncryptionId = *distribution.DefaultCacheBehavior.FieldLevelEncryptionId
		compress = *distribution.DefaultCacheBehavior.Compress
	}

	var quantity int
	if distribution.OriginGroups != nil {
		quantity = int(*distribution.OriginGroups.Quantity)
	}

	var cacheBehaviours []cloudfront.CacheBehaviour
	for _, cacheBehaviour := range config.DistributionConfig.CacheBehaviors.Items {
		cacheBehaviours = append(cacheBehaviours, cloudfront.CacheBehaviour{
			Metadata:             metadata,
			ViewerProtocolPolicy: defsecTypes.String(string(cacheBehaviour.ViewerProtocolPolicy), metadata),
		})
	}

	var minimumProtocolVersion string
	if distribution.ViewerCertificate != nil {
		minimumProtocolVersion = string(distribution.ViewerCertificate.MinimumProtocolVersion)
	}

	cloudFrontDefaultCertificate := distribution.ViewerCertificate.CloudFrontDefaultCertificate

	var geoRestrictionType string
	var geoItems []defsecTypes.StringValue
	if distribution.Restrictions.GeoRestriction != nil {
		geoRestrictionType = string(distribution.Restrictions.GeoRestriction.RestrictionType)
		for _, item := range distribution.Restrictions.GeoRestriction.Items {
			geoItems = append(geoItems, defsecTypes.String(item, metadata))
		}
	}

	var originItem []cloudfront.OriginItem
	for _, item := range distribution.Origins.Items {

		var originsslItem []defsecTypes.StringValue
		for _, sslitem := range item.CustomOriginConfig.OriginSslProtocols.Items {
			originsslItem = append(originsslItem, defsecTypes.String(string(sslitem), metadata))
		}
		originItem = append(originItem, cloudfront.OriginItem{
			Metadata: metadata,
			S3OriginConfig: cloudfront.S3OriginConfig{
				Metadata:             metadata,
				OriginAccessIdentity: defsecTypes.String(*item.S3OriginConfig.OriginAccessIdentity, metadata),
			},
			CustomOriginConfig: cloudfront.CustomOriginConfig{
				Metadata:                metadata,
				OriginProtocolPolicy:    defsecTypes.String(string(item.CustomOriginConfig.OriginProtocolPolicy), metadata),
				OriginSslProtocolsItems: originsslItem,
			},
		})
	}

	return &cloudfront.Distribution{
		Metadata: metadata,
		WAFID:    defsecTypes.String(wafID, metadata),
		Logging: cloudfront.Logging{
			Metadata: metadata,
			Bucket:   defsecTypes.String(loggingBucket, metadata),
		},
		DefaultCacheBehaviour: cloudfront.CacheBehaviour{
			Metadata:               metadata,
			ViewerProtocolPolicy:   defsecTypes.String(viewerProtocolPolicy, metadata),
			FieldLevelEncryptionId: defsecTypes.String(fieldLevelEncryptionId, metadata),
			Compress:               defsecTypes.Bool(compress, metadata),
		},
		OrdererCacheBehaviours: cacheBehaviours,
		ViewerCertificate: cloudfront.ViewerCertificate{
			Metadata:                     metadata,
			MinimumProtocolVersion:       defsecTypes.String(minimumProtocolVersion, metadata),
			CloudFrontDefaultCertificate: defsecTypes.Bool(*cloudFrontDefaultCertificate, metadata),
		},
		OriginGroups: cloudfront.OriginGroups{
			Metadata: metadata,
			Quantity: defsecTypes.Int(quantity, metadata),
		},
		Restrictions: cloudfront.Restrictions{
			Metadata:           metadata,
			GeoRestrictionType: defsecTypes.String(geoRestrictionType, metadata),
			GeoItems:           geoItems,
		},
		OriginItems: originItem,
		Etag:        defsecTypes.String(etag, metadata),
		DistributionConfig: cloudfront.DistributionConfig{
			Metadata: metadata,
			Logging:  defsecTypes.Bool(loggingenabled, metadata),
		},
	}, nil
}
