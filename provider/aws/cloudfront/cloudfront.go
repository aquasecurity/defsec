package cloudfront

import "github.com/aquasecurity/defsec/types"

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	WAFID                  types.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	Bucket types.StringValue
}

type CacheBehaviour struct {
	ViewerProtocolPolicy types.StringValue
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
	MinimumProtocolVersion types.StringValue
}
