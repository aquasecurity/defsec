package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/parser"
	"github.com/aquasecurity/defsec/provider/aws/cloudfront"
	"github.com/aquasecurity/defsec/types"
)

func getDistributions(ctx parser.FileContext) (distributions []cloudfront.Distribution) {

	distributionResources := ctx.GetResourceByType("AWS::CloudFront::Distribution")

	for _, r := range distributionResources {
		distribution := cloudfront.Distribution{
			Metadata:          r.Metadata(),
			WAFID: r.GetStringProperty("DistributionConfig.WebACLId"),
			Logging: cloudfront.Logging{
				Bucket: r.GetStringProperty("DistributionConfig.Logging.Bucket"),
			},
			DefaultCacheBehaviour:  getDefaultCacheBehaviour(r),
			OrdererCacheBehaviours: nil,
			ViewerCertificate: cloudfront.ViewerCertificate{
				MinimumProtocolVersion: r.GetStringProperty("DistributionConfig.ViewerCertificate.MinimumProtocolVersion"),
			},
		}

		distributions = append(distributions, distribution)
	}

	return distributions
}

func getDefaultCacheBehaviour(r *parser.Resource) cloudfront.CacheBehaviour {
	defaultCache := r.GetProperty("DistributionConfig.DefaultCacheBehavior")
	if defaultCache.IsNil() {
		return cloudfront.CacheBehaviour{
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}
	protoProp := r.GetProperty("DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy")
	if protoProp.IsNotString() {
		return cloudfront.CacheBehaviour{
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}

	return cloudfront.CacheBehaviour{
		ViewerProtocolPolicy: protoProp.AsStringValue(),
	}
}
