package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptDomainNamesV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.DomainName
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_domain_name" "example" {
}
`,
			expected: []apigateway.DomainName{
				{
					Name:           String(""),
					Version:        Int(1),
					SecurityPolicy: String("TLS_1_0"),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "aws_api_gateway_domain_name" "example" {
    domain_name = "testing.com"
    security_policy = "TLS_1_2"
}
`,
			expected: []apigateway.DomainName{
				{
					Name:           String("testing.com"),
					Version:        Int(1),
					SecurityPolicy: String("TLS_1_2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDomainNamesV1(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
