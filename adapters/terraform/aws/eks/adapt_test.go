package eks

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/providers/aws/eks"

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
				Metadata: types.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          types.NewTestMetadata(),
					API:               types.Bool(true, types.NewTestMetadata()),
					Authenticator:     types.Bool(true, types.NewTestMetadata()),
					Audit:             types.Bool(true, types.NewTestMetadata()),
					Scheduler:         types.Bool(true, types.NewTestMetadata()),
					ControllerManager: types.Bool(true, types.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: types.NewTestMetadata(),
					Secrets:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("key-arn", types.NewTestMetadata()),
				},
				PublicAccessEnabled: types.Bool(false, types.NewTestMetadata()),
				PublicAccessCIDRs: []types.StringValue{
					types.String("10.2.0.0/8", types.NewTestMetadata()),
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
				Metadata: types.NewTestMetadata(),
				Logging: eks.Logging{
					Metadata:          types.NewTestMetadata(),
					API:               types.Bool(false, types.NewTestMetadata()),
					Authenticator:     types.Bool(false, types.NewTestMetadata()),
					Audit:             types.Bool(false, types.NewTestMetadata()),
					Scheduler:         types.Bool(false, types.NewTestMetadata()),
					ControllerManager: types.Bool(false, types.NewTestMetadata()),
				},
				Encryption: eks.Encryption{
					Metadata: types.NewTestMetadata(),
					Secrets:  types.Bool(false, types.NewTestMetadata()),
					KMSKeyID: types.String("", types.NewTestMetadata()),
				},
				PublicAccessEnabled: types.Bool(true, types.NewTestMetadata()),
				PublicAccessCIDRs:   nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(t, test.terraform, ".tf")
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

	modules := testutil.CreateModulesFromSource(t, src, ".tf")
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
