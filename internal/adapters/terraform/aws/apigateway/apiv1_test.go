package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptAPIMethodsV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.RESTMethod
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_rest_api" "MyDemoAPI" {
  name        = "MyDemoAPI"
  description = "This is my API for demonstration purposes"
}

resource "aws_api_gateway_method" "example" {
    rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id
    http_method      = "GET"
    authorization    = "NONE"
}
`,
			expected: []apigateway.RESTMethod{
				{
					HTTPMethod:        String("GET"),
					AuthorizationType: String("NONE"),
					APIKeyRequired:    Bool(false),
				},
			},
		},
		{
			name: "basic",
			terraform: `
resource "aws_api_gateway_rest_api" "MyDemoAPI" {
  name        = "MyDemoAPI"
  description = "This is my API for demonstration purposes"
}

resource "aws_api_gateway_method" "example" {
    rest_api_id = aws_api_gateway_rest_api.MyDemoAPI.id
    http_method      = "GET"
    authorization    = "NONE"
    api_key_required = true
}
`,
			expected: []apigateway.RESTMethod{
				{
					HTTPMethod:        String("GET"),
					AuthorizationType: String("NONE"),
					APIKeyRequired:    Bool(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			restApiBlock := modules.GetBlocks()[1]
			adapted := adaptAPIMethodsV1(modules, restApiBlock)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptAPIsV1(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.API
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_api_gateway_rest_api" "example" {
    
}
`,
			expected: []apigateway.API{
				{
					Name:         String(""),
					Version:      Int(1),
					ProtocolType: String("REST"),
				},
			},
		},
		{
			name: "full",
			terraform: `
resource "aws_api_gateway_rest_api" "example" {
   name = "tfsec" 
}
`,
			expected: []apigateway.API{
				{
					Name:         String("tfsec"),
					Version:      Int(1),
					ProtocolType: String("REST"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptAPIsV1(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
