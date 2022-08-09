package sqs

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/liamg/iamgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sqs.SQS
	}{
		{
			name: "np kms key",
			terraform: `
			resource "aws_sqs_queue" "good_example" {

				policy = <<POLICY
				{
				  "Statement": [
					{
					  "Effect": "Allow",
					  "Action": "*"
					}
				  ]
				}
				POLICY
			}`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						QueueURL: types.String("", types.NewTestMetadata()),
						Encryption: sqs.Encryption{
							Metadata:          types.NewTestMetadata(),
							ManagedEncryption: types.Bool(false, types.NewTestMetadata()),
							KMSKeyID:          types.String("", types.NewTestMetadata()),
						},
						Policies: func() []iam.Policy {
							sb := iamgo.NewStatementBuilder()
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"*",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Metadata: types.NewTestMetadata(),
									Name:     types.StringDefault("", types.NewTestMetadata()),
									Document: iam.Document{
										Metadata: types.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
									Builtin: types.Bool(false, types.NewTestMetadata()),
								},
							}
						}(),
					},
				},
			},
		},
		{
			name: "no policy",
			terraform: `
			resource "aws_sqs_queue" "good_example" {
				kms_master_key_id = "/blah"
			}`,
			expected: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						QueueURL: types.String("", types.NewTestMetadata()),
						Encryption: sqs.Encryption{
							Metadata:          types.NewTestMetadata(),
							ManagedEncryption: types.Bool(false, types.NewTestMetadata()),
							KMSKeyID:          types.String("/blah", types.NewTestMetadata()),
						},
						Policies: nil,
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
	resource "aws_sqs_queue" "good_example" {
		kms_master_key_id = "key"

		policy = <<POLICY
		{
		  "Statement": [
			{
			  "Effect": "Allow",
			  "Action": "*"
			}
		  ]
		}
		POLICY
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Queues, 1)
	queue := adapted.Queues[0]

	assert.Equal(t, 2, queue.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, queue.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, queue.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, queue.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, queue.Policies[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, queue.Policies[0].GetMetadata().Range().GetEndLine())
}
