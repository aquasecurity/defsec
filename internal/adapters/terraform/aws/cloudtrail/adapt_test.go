package cloudtrail

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptTrail(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  cloudtrail.Trail
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_cloudtrail" "example" {
				name = "example"
				is_multi_region_trail = true
			  
				enable_log_file_validation = true
				kms_key_id = "kms-key"
				s3_bucket_name = "abcdefgh"
			}
`,
			expected: cloudtrail.Trail{
				Metadata:                types.NewTestMetadata(),
				Name:                    types.String("example", types.NewTestMetadata()),
				EnableLogFileValidation: types.Bool(true, types.NewTestMetadata()),
				IsMultiRegion:           types.Bool(true, types.NewTestMetadata()),
				KMSKeyID:                types.String("kms-key", types.NewTestMetadata()),
				BucketName:              types.String("abcdefgh", types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_cloudtrail" "example" {
			}
`,
			expected: cloudtrail.Trail{
				Metadata:                types.NewTestMetadata(),
				Name:                    types.String("", types.NewTestMetadata()),
				EnableLogFileValidation: types.Bool(false, types.NewTestMetadata()),
				IsMultiRegion:           types.Bool(false, types.NewTestMetadata()),
				KMSKeyID:                types.String("", types.NewTestMetadata()),
				BucketName:              types.String("", types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTrail(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_cloudtrail" "example" {
		name = "example"
		is_multi_region_trail = true
	  
		enable_log_file_validation = true
		kms_key_id = "kms-key"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Trails, 1)
	trail := adapted.Trails[0]

	assert.Equal(t, 2, trail.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, trail.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, trail.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, trail.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, trail.IsMultiRegion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, trail.IsMultiRegion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, trail.EnableLogFileValidation.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, trail.EnableLogFileValidation.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, trail.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, trail.KMSKeyID.GetMetadata().Range().GetEndLine())
}
