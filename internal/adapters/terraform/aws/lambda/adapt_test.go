package lambda

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  lambda.Lambda
	}{
		{
			name: "reference arn",
			terraform: `
			resource "aws_lambda_function" "example" {
				filename      = "lambda_function_payload.zip"
				function_name = ""
				role          = aws_iam_role.iam_for_lambda.arn
				runtime = ""

				tracing_config {
				  mode = "Passthrough"
				}
			  }

			  resource "aws_lambda_permission" "example" {
				statement_id = "AllowExecutionFromSNS"
				action = "lambda:InvokeFunction"
				function_name = aws_lambda_function.example.function_name
				principal = "sns.amazonaws.com"
				source_arn = aws_sns_topic.default.arn
			}
`,
			expected: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: defsecTypes.NewTestMetadata(),
							Mode:     defsecTypes.String("Passthrough", defsecTypes.NewTestMetadata()),
						},
						Permissions: []lambda.Permission{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								Principal: defsecTypes.String("sns.amazonaws.com", defsecTypes.NewTestMetadata()),
								SourceARN: defsecTypes.String("default", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults (with an orphan)",
			terraform: `
			resource "aws_lambda_function" "example" {
				tracing_config {
				}
			  }

			  resource "aws_lambda_permission" "example" {
			  }
`,
			expected: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: defsecTypes.NewTestMetadata(),
							Mode:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: defsecTypes.NewTestMetadata(),
							Mode:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
						Permissions: []lambda.Permission{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								Principal: defsecTypes.String("", defsecTypes.NewTestMetadata()),
								SourceARN: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},
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

func TestLines(t *testing.T) {
	src := `
	resource "aws_lambda_function" "example" {
		filename      = "lambda_function_payload.zip"
		function_name = ""
		role          = aws_iam_role.iam_for_lambda.arn
		runtime = ""

		tracing_config {
		  mode = "Passthrough"
		}
	  }

	  resource "aws_lambda_permission" "example" {
		statement_id = "AllowExecutionFromSNS"
		action = "lambda:InvokeFunction"
		function_name = aws_lambda_function.example.function_name
		principal = "sns.amazonaws.com"
		source_arn = "string arn"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Functions, 1)
	function := adapted.Functions[0]

	assert.Equal(t, 2, function.Metadata.Range().GetStartLine())
	assert.Equal(t, 11, function.Metadata.Range().GetEndLine())

	assert.Equal(t, 8, function.Tracing.Metadata.Range().GetStartLine())
	assert.Equal(t, 10, function.Tracing.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, function.Tracing.Mode.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, function.Tracing.Mode.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, function.Permissions[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 19, function.Permissions[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 17, function.Permissions[0].Principal.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, function.Permissions[0].Principal.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, function.Permissions[0].SourceARN.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, function.Permissions[0].SourceARN.GetMetadata().Range().GetEndLine())
}
