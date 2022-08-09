package cloudfront

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	types2.Metadata
	WAFID                  types2.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	types2.Metadata
	Bucket types2.StringValue
}

type CacheBehaviour struct {
	types2.Metadata
	ViewerProtocolPolicy types2.StringValue
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
	types2.Metadata
	MinimumProtocolVersion types2.StringValue
}
