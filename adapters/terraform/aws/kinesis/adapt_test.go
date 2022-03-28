package kinesis

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/aws/kinesis"
)

func Test_adaptStream(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  kinesis.Stream
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kinesis_stream" "example" {
				encryption_type = "KMS"
				kms_key_id = "my/special/key"
			}
`,
			expected: kinesis.Stream{
				Metadata: types.NewTestMetadata(),
				Encryption: kinesis.Encryption{
					Metadata: types.NewTestMetadata(),
					Type:     types.String("KMS", types.NewTestMetadata()),
					KMSKeyID: types.String("my/special/key", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_kinesis_stream" "example" {
			}
`,
			expected: kinesis.Stream{
				Metadata: types.NewTestMetadata(),
				Encryption: kinesis.Encryption{
					Metadata: types.NewTestMetadata(),
					Type:     types.String("", types.NewTestMetadata()),
					KMSKeyID: types.String("", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptStream(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kinesis_stream" "example" {
		encryption_type = "KMS"
		kms_key_id = "my/special/key"
	}`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.Streams, 1)
	stream := adapted.Streams[0]

	assert.Equal(t, 2, stream.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, stream.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, stream.Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, stream.Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, stream.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, stream.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
