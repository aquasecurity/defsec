package dms

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/aquasecurity/defsec/pkg/providers/aws/dms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getReplicationInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dms.ReplicationInstance
	}{
		{
			name: "configured",
			terraform: `		
			resource "aws_dms_replication_instance" "dms" {
				auto_minor_version_upgrade   = true
				multi_az                     = false
				publicly_accessible          = true
			}
`,
			expected: dms.ReplicationInstance{
				Metadata:                defsecTypes.NewTestMetadata(),
				AutoMinorVersionUpgrade: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				MultiAZ:                 defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				PubliclyAccessible:      defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `		
			resource "aws_dms_replication_instance" "dms" {
			}
`,
			expected: dms.ReplicationInstance{
				Metadata:                defsecTypes.NewTestMetadata(),
				AutoMinorVersionUpgrade: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				MultiAZ:                 defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				PubliclyAccessible:      defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptReplicationInstance(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_dms_replication_instance" "dms" {
		auto_minor_version_upgrade   = true
		multi_az                     = false
		publicly_accessible          = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.ReplicationInstances, 1)

	replicationInstance := adapted.ReplicationInstances[0]

	assert.Equal(t, 2, replicationInstance.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, replicationInstance.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, replicationInstance.AutoMinorVersionUpgrade.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, replicationInstance.AutoMinorVersionUpgrade.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, replicationInstance.MultiAZ.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, replicationInstance.MultiAZ.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, replicationInstance.PubliclyAccessible.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, replicationInstance.PubliclyAccessible.GetMetadata().Range().GetEndLine())

}
