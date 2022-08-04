package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	v2 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v2"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptDomainNamesV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []v2.DomainName
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_domain_name" "example" {
}
`,
			expected: []v2.DomainName{
				{
					Name:           String(""),
					SecurityPolicy: String("TLS_1_0"),
				},
			},
		},
		{
			name: "fully populated",
			terraform: `
resource "aws_apigatewayv2_domain_name" "example" {
                domain_name = "testing.com"
                domain_name_configuration {
                    security_policy = "TLS_1_2"
                }
}
`,
			expected: []v2.DomainName{
				{
					Name:           String("testing.com"),
					SecurityPolicy: String("TLS_1_2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDomainNamesV2(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
