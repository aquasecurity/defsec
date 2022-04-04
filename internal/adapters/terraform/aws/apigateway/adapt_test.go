package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.APIGateway
	}{
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
}
resource "aws_apigatewayv2_api" "example" {
    name = "tfsec"
    protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "example" {
    api_id = aws_apigatewayv2_api.example.id
    name = "tfsec" 
    access_log_settings {
        destination_arn = "arn:123"
    }
}

resource "aws_api_gateway_domain_name" "example" {
    domain_name = "v1.com"
    security_policy = "TLS_1_0"
}

resource "aws_apigatewayv2_domain_name" "example" {
    domain_name = "v2.com"
    domain_name_configuration {
        security_policy = "TLS_1_2"
    }
}
`,
			expected: apigateway.APIGateway{
				APIs: []apigateway.API{
					{
						Name:         String("MyDemoAPI"),
						Version:      Int(1),
						ProtocolType: String("REST"),
						RESTMethods: []apigateway.RESTMethod{
							{
								HTTPMethod:        String("GET"),
								AuthorizationType: String("NONE"),
								APIKeyRequired:    Bool(false),
							},
						},
					},
					{
						Name:         String("tfsec"),
						Version:      Int(2),
						ProtocolType: String("HTTP"),
						Stages: []apigateway.Stage{
							{
								Version: Int(2),
								Name:    String("tfsec"),
								AccessLogging: apigateway.AccessLogging{
									CloudwatchLogGroupARN: String("arn:123"),
								},
								RESTMethodSettings: apigateway.RESTMethodSettings{
									CacheDataEncrypted: Bool(true),
								},
							},
						},
					},
				},
				DomainNames: []apigateway.DomainName{
					{
						Name:           String("v1.com"),
						Version:        Int(1),
						SecurityPolicy: String("TLS_1_0"),
					},
					{
						Name:           String("v2.com"),
						Version:        Int(2),
						SecurityPolicy: String("TLS_1_2"),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Int(i int) types.IntValue {
	return types.Int(i, types.NewTestMetadata())
}

func Bool(b bool) types.BoolValue {
	return types.Bool(b, types.NewTestMetadata())
}

func String(s string) types.StringValue {
	return types.String(s, types.NewTestMetadata())
}
