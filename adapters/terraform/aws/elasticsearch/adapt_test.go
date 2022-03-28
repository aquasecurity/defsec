package elasticsearch

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/aws/elasticsearch"
)

func Test_adaptDomain(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  elasticsearch.Domain
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_elasticsearch_domain" "example" {
				domain_name = "domain-foo"
			  
				node_to_node_encryption {
					enabled = true
				}
	 
				encrypt_at_rest {
					enabled = true
				}

				domain_endpoint_options {
				  enforce_https = true
				  tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
				}

				log_publishing_options {
					cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
					log_type                 = "AUDIT_LOGS"
					enabled                  = true  
				}
			  }
`,
			expected: elasticsearch.Domain{
				Metadata:   types.NewTestMetadata(),
				DomainName: types.String("domain-foo", types.NewTestMetadata()),
				LogPublishing: elasticsearch.LogPublishing{
					Metadata:     types.NewTestMetadata(),
					AuditEnabled: types.Bool(true, types.NewTestMetadata()),
				},
				TransitEncryption: elasticsearch.TransitEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
				},
				AtRestEncryption: elasticsearch.AtRestEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
				},
				Endpoint: elasticsearch.Endpoint{
					Metadata:     types.NewTestMetadata(),
					EnforceHTTPS: types.Bool(true, types.NewTestMetadata()),
					TLSPolicy:    types.String("Policy-Min-TLS-1-2-2019-07", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_elasticsearch_domain" "example" {
			  }
`,
			expected: elasticsearch.Domain{
				Metadata:   types.NewTestMetadata(),
				DomainName: types.String("", types.NewTestMetadata()),
				LogPublishing: elasticsearch.LogPublishing{
					Metadata:     types.NewTestMetadata(),
					AuditEnabled: types.Bool(false, types.NewTestMetadata()),
				},
				TransitEncryption: elasticsearch.TransitEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(false, types.NewTestMetadata()),
				},
				AtRestEncryption: elasticsearch.AtRestEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(false, types.NewTestMetadata()),
				},
				Endpoint: elasticsearch.Endpoint{
					Metadata:     types.NewTestMetadata(),
					EnforceHTTPS: types.Bool(false, types.NewTestMetadata()),
					TLSPolicy:    types.String("", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptDomain(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_elasticsearch_domain" "example" {
		domain_name = "domain-foo"
	  
		node_to_node_encryption {
			enabled = true
		}

		encrypt_at_rest {
			enabled = true
		}

		domain_endpoint_options {
		  enforce_https = true
		  tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
		}

		log_publishing_options {
			cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
			log_type                 = "AUDIT_LOGS"
			enabled                  = true  
		}
	  }`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.Domains, 1)
	domain := adapted.Domains[0]

	assert.Equal(t, 2, domain.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, domain.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, domain.DomainName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, domain.DomainName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, domain.TransitEncryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, domain.TransitEncryption.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, domain.TransitEncryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, domain.TransitEncryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, domain.AtRestEncryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, domain.AtRestEncryption.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, domain.AtRestEncryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, domain.AtRestEncryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, domain.Endpoint.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, domain.Endpoint.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, domain.Endpoint.EnforceHTTPS.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, domain.Endpoint.EnforceHTTPS.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, domain.Endpoint.TLSPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, domain.Endpoint.TLSPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, domain.LogPublishing.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, domain.LogPublishing.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, domain.LogPublishing.AuditEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, domain.LogPublishing.AuditEnabled.GetMetadata().Range().GetEndLine())
}
