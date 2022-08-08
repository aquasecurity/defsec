package sns

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptTopic(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sns.Topic
	}{
		{
			name: "defined",
			terraform: `
			resource "aws_sns_topic" "good_example" {
				kms_master_key_id = "/blah"
			}
`,
			expected: sns.Topic{
				Metadata: types.NewTestMetadata(),
				ARN:      types.String("", types.NewTestMetadata()),
				Encryption: sns.Encryption{
					Metadata: types.NewTestMetadata(),
					KMSKeyID: types.String("/blah", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "default",
			terraform: `
			resource "aws_sns_topic" "good_example" {
			}
`,
			expected: sns.Topic{
				Metadata: types.NewTestMetadata(),
				ARN:      types.String("", types.NewTestMetadata()),
				Encryption: sns.Encryption{
					Metadata: types.NewTestMetadata(),
					KMSKeyID: types.String("", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTopic(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_sns_topic" "good_example" {
		kms_master_key_id = "/blah"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Topics, 1)
	topic := adapted.Topics[0]

	assert.Equal(t, 2, topic.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, topic.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, topic.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, topic.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
