package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/providers/aws/apigateway"
)

func Test_adaptAPIsV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []apigateway.API
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_api" "example" {
    protocol_type = "HTTP"
}
`,
			expected: []apigateway.API{
				{
					Name:         String(""),
					Version:      Int(2),
					ProtocolType: String("HTTP"),
				},
			},
		},
		{
			name: "full",
			terraform: `
resource "aws_apigatewayv2_api" "example" {
    name = "tfsec"
    protocol_type = "HTTP"
}
`,
			expected: []apigateway.API{
				{
					Name:         String("tfsec"),
					Version:      Int(2),
					ProtocolType: String("HTTP"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptAPIsV2(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptStageV2(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  apigateway.Stage
	}{
		{
			name: "defaults",
			terraform: `
resource "aws_apigatewayv2_stage" "example" {
    
}
`,
			expected: apigateway.Stage{
				Name:    String(""),
				Version: Int(2),
				AccessLogging: apigateway.AccessLogging{
					CloudwatchLogGroupARN: String(""),
				},
				RESTMethodSettings: apigateway.RESTMethodSettings{
					CacheDataEncrypted: Bool(true),
				},
			},
		},
		{
			name: "basics",
			terraform: `
resource "aws_apigatewayv2_stage" "example" {
    name = "tfsec" 
    access_log_settings {
        destination_arn = "arn:123"
    }
}
`,
			expected: apigateway.Stage{
				Name:    String("tfsec"),
				Version: Int(2),
				AccessLogging: apigateway.AccessLogging{
					CloudwatchLogGroupARN: String("arn:123"),
				},
				RESTMethodSettings: apigateway.RESTMethodSettings{
					CacheDataEncrypted: Bool(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptStageV2(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
