package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
									CacheEnabled:       Bool(false),
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
func TestLines(t *testing.T) {
	src := `
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

	`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.APIs, 2)
	require.Len(t, adapted.DomainNames, 1)

	apiV1 := adapted.APIs[0]
	apiV2 := adapted.APIs[1]
	domainName := adapted.DomainNames[0]

	assert.Equal(t, 2, apiV1.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, apiV1.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, apiV1.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, apiV1.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, apiV1.RESTMethods[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, apiV1.RESTMethods[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, apiV1.RESTMethods[0].HTTPMethod.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, apiV1.RESTMethods[0].HTTPMethod.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, apiV1.RESTMethods[0].AuthorizationType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, apiV1.RESTMethods[0].AuthorizationType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, apiV1.RESTMethods[0].APIKeyRequired.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, apiV1.RESTMethods[0].APIKeyRequired.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, apiV2.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, apiV2.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, apiV2.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, apiV2.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, apiV2.ProtocolType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, apiV2.ProtocolType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, apiV2.Stages[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, apiV2.Stages[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, apiV2.Stages[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, apiV2.Stages[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, apiV2.Stages[0].AccessLogging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, apiV2.Stages[0].AccessLogging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, apiV2.Stages[0].AccessLogging.CloudwatchLogGroupARN.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, apiV2.Stages[0].AccessLogging.CloudwatchLogGroupARN.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 27, domainName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, domainName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 28, domainName.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, domainName.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 29, domainName.SecurityPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 29, domainName.SecurityPolicy.GetMetadata().Range().GetEndLine())

}
