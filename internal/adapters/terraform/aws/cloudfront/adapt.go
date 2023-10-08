package cloudfront

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) cloudfront.Cloudfront {
	return cloudfront.Cloudfront{
		Distributions: adaptDistributions(modules),
	}
}

func adaptDistributions(modules terraform.Modules) []cloudfront.Distribution {
	var distributions []cloudfront.Distribution
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudfront_distribution") {
			distributions = append(distributions, adaptDistribution(resource))
		}
	}
	return distributions
}

func adaptDistribution(resource *terraform.Block) cloudfront.Distribution {

	distribution := cloudfront.Distribution{
		Metadata: resource.GetMetadata(),
		WAFID:    types.StringDefault("", resource.GetMetadata()),
		Logging: cloudfront.Logging{
			Metadata: resource.GetMetadata(),
			Bucket:   types.StringDefault("", resource.GetMetadata()),
		},
		DefaultCacheBehaviour: cloudfront.CacheBehaviour{
			Metadata:               resource.GetMetadata(),
			ViewerProtocolPolicy:   types.String("allow-all", resource.GetMetadata()),
			FieldLevelEncryptionId: types.String("", resource.GetMetadata()),
			Compress:               types.Bool(true, resource.GetMetadata()),
		},
		OrdererCacheBehaviours: nil,
		ViewerCertificate: cloudfront.ViewerCertificate{
			Metadata:                     resource.GetMetadata(),
			MinimumProtocolVersion:       types.StringDefault("TLSv1", resource.GetMetadata()),
			CloudFrontDefaultCertificate: types.BoolDefault(true, resource.GetMetadata()),
		},
		OriginGroups: cloudfront.OriginGroups{
			Metadata: resource.GetMetadata(),
			Quantity: types.Int(0, resource.GetMetadata()),
		},
		Restrictions: cloudfront.Restrictions{
			Metadata:           resource.GetMetadata(),
			GeoRestrictionType: types.String("", resource.GetMetadata()),
			GeoItems:           nil,
		},
		Etag:        resource.GetAttribute("etag").AsStringValueOrDefault("", resource),
		OriginItems: nil,
	}

	distribution.WAFID = resource.GetAttribute("web_acl_id").AsStringValueOrDefault("", resource)

	if loggingBlock := resource.GetBlock("logging_config"); loggingBlock.IsNotNil() {
		distribution.Logging.Metadata = loggingBlock.GetMetadata()
		bucketAttr := loggingBlock.GetAttribute("bucket")
		distribution.Logging.Bucket = bucketAttr.AsStringValueOrDefault("", loggingBlock)
	}

	if defaultCacheBlock := resource.GetBlock("default_cache_behavior"); defaultCacheBlock.IsNotNil() {
		distribution.DefaultCacheBehaviour.Metadata = defaultCacheBlock.GetMetadata()
		viewerProtocolPolicyAttr := defaultCacheBlock.GetAttribute("viewer_protocol_policy")
		distribution.DefaultCacheBehaviour.ViewerProtocolPolicy = viewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", defaultCacheBlock)
		fieldLevelEncryptionIdAttr := defaultCacheBlock.GetAttribute("field_level_encryption_id")
		distribution.DefaultCacheBehaviour.FieldLevelEncryptionId = fieldLevelEncryptionIdAttr.AsStringValueOrDefault("", defaultCacheBlock)
		compressAttr := defaultCacheBlock.GetAttribute("compress")
		distribution.DefaultCacheBehaviour.Compress = compressAttr.AsBoolValueOrDefault(true, defaultCacheBlock)
	}

	orderedCacheBlocks := resource.GetBlocks("ordered_cache_behavior")
	for _, orderedCacheBlock := range orderedCacheBlocks {
		viewerProtocolPolicyAttr := orderedCacheBlock.GetAttribute("viewer_protocol_policy")
		viewerProtocolPolicyVal := viewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", orderedCacheBlock)
		distribution.OrdererCacheBehaviours = append(distribution.OrdererCacheBehaviours, cloudfront.CacheBehaviour{
			Metadata:             orderedCacheBlock.GetMetadata(),
			ViewerProtocolPolicy: viewerProtocolPolicyVal,
		})
	}

	originBlock := resource.GetBlocks("origin")
	for _, origin := range originBlock {
		var OAI, OPP types.StringValue
		var sslItems []types.StringValue
		if S3originblock := origin.GetBlock("s3_origin_config"); S3originblock.IsNotNil() {
			OAI = S3originblock.GetAttribute("origin_access_identity").AsStringValueOrDefault("", S3originblock)
		}
		if customOriginBlock := origin.GetBlock("custom_origin_config"); customOriginBlock.IsNotNil() {
			OPP = customOriginBlock.GetAttribute("origin_protocol_policy").AsStringValueOrDefault("match-viewer", customOriginBlock)
			sslAttr := origin.GetAttribute("origin_ssl_protocols")
			for _, ssl := range sslAttr.AsStringValues() {
				sslItems = append(sslItems, ssl)
			}
		}
		distribution.OriginItems = append(distribution.OriginItems, cloudfront.OriginItem{
			Metadata: origin.GetMetadata(),
			S3OriginConfig: cloudfront.S3OriginConfig{
				Metadata:             origin.GetMetadata(),
				OriginAccessIdentity: OAI,
			},
			CustomOriginConfig: cloudfront.CustomOriginConfig{
				Metadata:                origin.GetMetadata(),
				OriginProtocolPolicy:    OPP,
				OriginSslProtocolsItems: sslItems,
			},
		})
	}

	if viewerCertBlock := resource.GetBlock("viewer_certificate"); viewerCertBlock.IsNotNil() {
		distribution.ViewerCertificate.Metadata = viewerCertBlock.GetMetadata()
		minProtocolAttr := viewerCertBlock.GetAttribute("minimum_protocol_version")
		distribution.ViewerCertificate.MinimumProtocolVersion = minProtocolAttr.AsStringValueOrDefault("TLSv1", viewerCertBlock)
		cloudfrontDefaulAttr := viewerCertBlock.GetAttribute("cloudfront_default_certificate")
		distribution.ViewerCertificate.CloudFrontDefaultCertificate = cloudfrontDefaulAttr.AsBoolValueOrDefault(true, viewerCertBlock)
	}

	if restrictionblock := resource.GetBlock("restrictions"); restrictionblock.IsNotNil() {
		if georesblock := restrictionblock.GetBlock("geo_restriction"); georesblock.IsNotNil() {
			distribution.Restrictions.Metadata = georesblock.GetMetadata()
			typeAttr := georesblock.GetAttribute("restriction_type")
			distribution.Restrictions.GeoRestrictionType = typeAttr.AsStringValueOrDefault("", georesblock)
			var locations []types.StringValue
			itemAttr := georesblock.GetAttribute("locations")
			for _, item := range itemAttr.AsStringValues() {
				locations = append(locations, item)
			}
			distribution.Restrictions.GeoItems = locations
		}
	}

	return distribution
}
