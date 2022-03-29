package neptune

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/aws/neptune"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  neptune.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_neptune_cluster" "example" {
				enable_cloudwatch_logs_exports      = ["audit"]
				storage_encrypted                   = true
				kms_key_arn                         = "kms-key"
			  }
`,
			expected: neptune.Cluster{
				Metadata: types.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: types.NewTestMetadata(),
					Audit:    types.Bool(true, types.NewTestMetadata()),
				},
				StorageEncrypted: types.Bool(true, types.NewTestMetadata()),
				KMSKeyID:         types.String("kms-key", types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_neptune_cluster" "example" {
			  }
`,
			expected: neptune.Cluster{
				Metadata: types.NewTestMetadata(),
				Logging: neptune.Logging{
					Metadata: types.NewTestMetadata(),
					Audit:    types.Bool(false, types.NewTestMetadata()),
				},
				StorageEncrypted: types.Bool(false, types.NewTestMetadata()),
				KMSKeyID:         types.String("", types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_neptune_cluster" "example" {
		enable_cloudwatch_logs_exports      = ["audit"]
		storage_encrypted                   = true
		kms_key_arn                         = "kms-key"
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, cluster.Logging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.Logging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, cluster.Logging.Audit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.Logging.Audit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.StorageEncrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.StorageEncrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.KMSKeyID.GetMetadata().Range().GetEndLine())
}
