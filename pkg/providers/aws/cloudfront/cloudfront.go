package cloudfront

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	Metadata               defsecTypes.Metadata
	WAFID                  defsecTypes.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
	OriginGroups           OriginGroups
	Restrictions           Restrictions
	OriginItems            []OriginItem
	Etag                   defsecTypes.StringValue
	DistributionConfig     DistributionConfig
}

type DistributionConfig struct {
	Metadata defsecTypes.Metadata
	Logging  defsecTypes.BoolValue
}
type OriginItem struct {
	Metadata           defsecTypes.Metadata
	S3OriginConfig     S3OriginConfig
	CustomOriginConfig CustomOriginConfig
}

type CustomOriginConfig struct {
	Metadata                defsecTypes.Metadata
	OriginProtocolPolicy    defsecTypes.StringValue
	OriginSslProtocolsItems []defsecTypes.StringValue
}

type S3OriginConfig struct {
	Metadata             defsecTypes.Metadata
	OriginAccessIdentity defsecTypes.StringValue
}

type Restrictions struct {
	Metadata           defsecTypes.Metadata
	GeoRestrictionType defsecTypes.StringValue
	GeoItems           []defsecTypes.StringValue
}

type OriginGroups struct {
	Metadata defsecTypes.Metadata
	Quantity defsecTypes.IntValue
}

type Logging struct {
	Metadata defsecTypes.Metadata
	Bucket   defsecTypes.StringValue
}

type CacheBehaviour struct {
	Metadata               defsecTypes.Metadata
	ViewerProtocolPolicy   defsecTypes.StringValue
	FieldLevelEncryptionId defsecTypes.StringValue
	Compress               defsecTypes.BoolValue
}

const (
	ViewerPolicyProtocolAllowAll        = "allow-all"
	ViewerPolicyProtocolHTTPSOnly       = "https-only"
	ViewerPolicyProtocolRedirectToHTTPS = "redirect-to-https"
)

const (
	ProtocolVersionTLS1_2 = "TLSv1.2_2021"
)

type ViewerCertificate struct {
	Metadata                     defsecTypes.Metadata
	CloudFrontDefaultCertificate defsecTypes.BoolValue
	MinimumProtocolVersion       defsecTypes.StringValue
}
