package cloudfront

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	defsecTypes.Metadata
	WAFID                  defsecTypes.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	defsecTypes.Metadata
	Bucket defsecTypes.StringValue
}

type CacheBehaviour struct {
	defsecTypes.Metadata
	ViewerProtocolPolicy defsecTypes.StringValue
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
	defsecTypes.Metadata
	MinimumProtocolVersion defsecTypes.StringValue
}
