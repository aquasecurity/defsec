package cloudfront

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getDistributions(ctx parser.FileContext) (distributions []cloudfront.Distribution) {

	distributionResources := ctx.GetResourcesByType("AWS::CloudFront::Distribution")

	for _, r := range distributionResources {
		distribution := cloudfront.Distribution{
			Metadata: r.Metadata(),
			WAFID:    r.GetStringProperty("DistributionConfig.WebACLId"),
			Logging: cloudfront.Logging{
				Metadata: r.Metadata(),
				Bucket:   r.GetStringProperty("DistributionConfig.Logging.Bucket"),
			},
			DefaultCacheBehaviour:  getDefaultCacheBehaviour(r),
			OrdererCacheBehaviours: nil,
			ViewerCertificate: cloudfront.ViewerCertificate{
				Metadata:                     r.Metadata(),
				MinimumProtocolVersion:       r.GetStringProperty("DistributionConfig.ViewerCertificate.MinimumProtocolVersion"),
				CloudFrontDefaultCertificate: r.GetBoolProperty("DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate"),
			},
			OriginGroups: cloudfront.OriginGroups{
				Metadata: r.Metadata(),
				Quantity: r.GetIntProperty("DistributionConfig.OriginGroups.Quantity"),
			},
			Restrictions: cloudfront.Restrictions{
				Metadata:           r.Metadata(),
				GeoRestrictionType: r.GetStringProperty("DistributionConfig.GeoRestriction.RestrictionType"),
				GeoItems:           getlocations(r),
			},
			Etag:        types.String("", r.Metadata()),
			OriginItems: getorigins(r),
		}

		distributions = append(distributions, distribution)
	}

	return distributions
}

func getDefaultCacheBehaviour(r *parser.Resource) cloudfront.CacheBehaviour {
	defaultCache := r.GetProperty("DistributionConfig.DefaultCacheBehavior")
	if defaultCache.IsNil() {
		return cloudfront.CacheBehaviour{
			Metadata:               r.Metadata(),
			ViewerProtocolPolicy:   types.StringDefault("allow-all", r.Metadata()),
			FieldLevelEncryptionId: types.StringDefault("", r.Metadata()),
			Compress:               types.BoolDefault(true, r.Metadata()),
		}
	}
	protoProp := r.GetProperty("DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy")
	if protoProp.IsNotString() {
		return cloudfront.CacheBehaviour{
			Metadata:             r.Metadata(),
			ViewerProtocolPolicy: types.StringDefault("allow-all", r.Metadata()),
		}
	}
	encrypProp := r.GetProperty("DistributionConfig.DefaultCacheBehavior.FieldLevelEncryptionId")
	if encrypProp.IsNotString() {
		return cloudfront.CacheBehaviour{
			Metadata:               r.Metadata(),
			FieldLevelEncryptionId: types.StringDefault("", r.Metadata()),
		}
	}
	compressProp := r.GetProperty("DistributionConfig.DefaultCacheBehavior.Compress")
	if compressProp.IsNotBool() {
		return cloudfront.CacheBehaviour{
			Metadata: r.Metadata(),
			Compress: types.BoolDefault(true, r.Metadata()),
		}
	}

	return cloudfront.CacheBehaviour{
		Metadata:               r.Metadata(),
		ViewerProtocolPolicy:   protoProp.AsStringValue(),
		FieldLevelEncryptionId: encrypProp.AsStringValue(),
		Compress:               compressProp.AsBoolValue(),
	}
}

func getlocations(r *parser.Resource) []types.StringValue {
	Lres := r.GetProperty("DistributionConfig.GeoRestriction.Locations")
	var locations []types.StringValue
	if Lres.IsNil() || Lres.IsNotList() {
		return locations
	}

	for _, l := range Lres.AsList() {
		locations = append(locations, l.AsStringValue())
	}
	return locations
}

func getorigins(r *parser.Resource) []cloudfront.OriginItem {
	originRes := r.GetProperty("DistributionConfig.Origin")
	var origins []cloudfront.OriginItem
	if originRes.IsNil() || originRes.IsNotList() {
		return origins
	}

	for _, o := range originRes.AsList() {

		var sslItem []types.StringValue
		for _, ssl := range o.GetProperty("CustomOriginConfig.OriginSSLProtocols").AsList() {
			sslItem = append(sslItem, ssl.AsStringValue())
		}
		origins = append(origins, cloudfront.OriginItem{
			Metadata: o.Metadata(),
			S3OriginConfig: cloudfront.S3OriginConfig{
				Metadata:             o.Metadata(),
				OriginAccessIdentity: o.GetStringProperty("S3OriginConfig.OriginAccessIdentity"),
			},
			CustomOriginConfig: cloudfront.CustomOriginConfig{
				Metadata:                o.Metadata(),
				OriginProtocolPolicy:    o.GetStringProperty("CustomOriginConfig.OriginProtocolPolicy"),
				OriginSslProtocolsItems: sslItem,
			},
		})
	}
	return origins
}
