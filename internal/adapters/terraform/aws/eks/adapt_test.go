package eks

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  eks.Cluster
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_eks_cluster" "example" {
				encryption_config {
					resources = [ "secrets" ]
					provider {
						key_arn = "key-arn"
					}
				}
			
				enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
			
				name = "good_example_cluster"
				role_arn = var.cluster_arn
				vpc_config {
					endpoint_public_access = false
					public_access_cidrs = ["10.2.0.0/8"]
				}
			}
`,
			expected: eks.Cluster{
				Metadata: types2.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          types2.NewTestMetadata(),
					API:               types2.Bool(true, types2.NewTestMetadata()),
					Authenticator:     types2.Bool(true, types2.NewTestMetadata()),
					Audit:             types2.Bool(true, types2.NewTestMetadata()),
					Scheduler:         types2.Bool(true, types2.NewTestMetadata()),
					ControllerManager: types2.Bool(true, types2.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: types2.NewTestMetadata(),
					Secrets:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("key-arn", types2.NewTestMetadata()),
				},
				PublicAccessEnabled: types2.Bool(false, types2.NewTestMetadata()),
				PublicAccessCIDRs: []types2.StringValue{
					types2.String("10.2.0.0/8", types2.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_eks_cluster" "example" {
			}
`,
			expected: eks.Cluster{
				Metadata: types2.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          types2.NewTestMetadata(),
					API:               types2.Bool(false, types2.NewTestMetadata()),
					Authenticator:     types2.Bool(false, types2.NewTestMetadata()),
					Audit:             types2.Bool(false, types2.NewTestMetadata()),
					Scheduler:         types2.Bool(false, types2.NewTestMetadata()),
					ControllerManager: types2.Bool(false, types2.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: types2.NewTestMetadata(),
					Secrets:  types2.Bool(false, types2.NewTestMetadata()),
					KMSKeyID: types2.String("", types2.NewTestMetadata()),
				},
				PublicAccessEnabled: types2.Bool(true, types2.NewTestMetadata()),
				PublicAccessCIDRs:   nil,
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
	resource "aws_eks_cluster" "example" {
		encryption_config {
			resources = [ "secrets" ]
			provider {
				key_arn = "key-arn"
			}
		}
	
		enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
	
		name = "good_example_cluster"
		role_arn = var.cluster_arn
		vpc_config {
			endpoint_public_access = false
			public_access_cidrs = ["10.2.0.0/8"]
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, cluster.Encryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, cluster.Encryption.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.Encryption.Secrets.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.Secrets.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.API.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.API.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Audit.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Audit.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Authenticator.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Authenticator.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.Scheduler.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.Scheduler.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.Logging.ControllerManager.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.Logging.ControllerManager.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, cluster.PublicAccessEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, cluster.PublicAccessEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, cluster.PublicAccessCIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, cluster.PublicAccessCIDRs[0].GetMetadata().Range().GetEndLine())

}
