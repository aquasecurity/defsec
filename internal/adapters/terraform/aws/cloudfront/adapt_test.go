package cloudfront

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudfront"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptDistribution(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cloudfront.Distribution
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_cloudfront_distribution" "example" {
				logging_config {
					bucket          = "mylogs.s3.amazonaws.com"
				}
				
				web_acl_id = "waf_id"

				default_cache_behavior {
					viewer_protocol_policy = "redirect-to-https"
				}

				ordered_cache_behavior {
					viewer_protocol_policy = "redirect-to-https"
				  }

				viewer_certificate {
					cloudfront_default_certificate = true
					minimum_protocol_version = "TLSv1.2_2021"
				}
			}
`,
			expected: cloudfront.Distribution{
				Metadata: types2.NewTestMetadata(),
				WAFID:    types2.String("waf_id", types2.NewTestMetadata()),
				Logging: cloudfront.Logging{
					Metadata: types2.NewTestMetadata(),
					Bucket:   types2.String("mylogs.s3.amazonaws.com", types2.NewTestMetadata()),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					Metadata:             types2.NewTestMetadata(),
					ViewerProtocolPolicy: types2.String("redirect-to-https", types2.NewTestMetadata()),
				},
				OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
					{
						Metadata:             types2.NewTestMetadata(),
						ViewerProtocolPolicy: types2.String("redirect-to-https", types2.NewTestMetadata()),
					},
				},
				ViewerCertificate: cloudfront.ViewerCertificate{
					Metadata:               types2.NewTestMetadata(),
					MinimumProtocolVersion: types2.String("TLSv1.2_2021", types2.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_cloudfront_distribution" "example" {
			}
`,
			expected: cloudfront.Distribution{
				Metadata: types2.NewTestMetadata(),
				WAFID:    types2.String("", types2.NewTestMetadata()),
				Logging: cloudfront.Logging{
					Metadata: types2.NewTestMetadata(),
					Bucket:   types2.String("", types2.NewTestMetadata()),
				},
				DefaultCacheBehaviour: cloudfront.CacheBehaviour{
					Metadata:             types2.NewTestMetadata(),
					ViewerProtocolPolicy: types2.String("allow-all", types2.NewTestMetadata()),
				},

				ViewerCertificate: cloudfront.ViewerCertificate{
					Metadata:               types2.NewTestMetadata(),
					MinimumProtocolVersion: types2.String("TLSv1", types2.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDistribution(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudfront_distribution" "example" {
		logging_config {
			bucket          = "mylogs.s3.amazonaws.com"
		}
		
		web_acl_id = "waf_id"

		default_cache_behavior {
			viewer_protocol_policy = "redirect-to-https"
		}

		ordered_cache_behavior {
			viewer_protocol_policy = "redirect-to-https"
		  }

		viewer_certificate {
			cloudfront_default_certificate = true
			minimum_protocol_version = "TLSv1.2_2021"
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Distributions, 1)
	distribution := adapted.Distributions[0]

	assert.Equal(t, 2, distribution.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, distribution.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, distribution.Logging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, distribution.Logging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, distribution.WAFID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, distribution.WAFID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, distribution.DefaultCacheBehaviour.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, distribution.DefaultCacheBehaviour.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, distribution.DefaultCacheBehaviour.ViewerProtocolPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, distribution.DefaultCacheBehaviour.ViewerProtocolPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, distribution.OrdererCacheBehaviours[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, distribution.OrdererCacheBehaviours[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, distribution.OrdererCacheBehaviours[0].ViewerProtocolPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, distribution.OrdererCacheBehaviours[0].ViewerProtocolPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, distribution.ViewerCertificate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 20, distribution.ViewerCertificate.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, distribution.ViewerCertificate.MinimumProtocolVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, distribution.ViewerCertificate.MinimumProtocolVersion.GetMetadata().Range().GetEndLine())
}
