package cloudfront

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/rules"
	"github.com/aquasecurity/cfsec/internal/app/cfsec/scanner"
	"github.com/aquasecurity/defsec/rules/aws/cloudfront"
)

func init() {
	scanner.RegisterCheckRule(rules.Rule{

		BadExample: []string{
			`---
Resources:
  BadExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.0
    Type: AWS::CloudFront::Distribution
`,
		},

		GoodExample: []string{
			`---
Resources:
  GoodExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2021
    Type: AWS::CloudFront::Distribution
`,
		},

		Base: cloudfront.CheckUseSecureTlsPolicy,
	})
}
