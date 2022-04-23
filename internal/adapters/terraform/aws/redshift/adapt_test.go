package redshift

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/redshift"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.Redshift
	}{
		{
			name: "reference key id",
			terraform: `
			resource "aws_kms_key" "redshift" {
				enable_key_rotation = true
			}
			
			resource "aws_redshift_cluster" "example" {
			  cluster_identifier = "tf-redshift-cluster"
			  encrypted          = true
			  kms_key_id         = aws_kms_key.redshift.key_id
			  cluster_subnet_group_name = "redshift_subnet"
			}

			resource "aws_redshift_security_group" "default" {
				name = "redshift-sg"
				description = "some description"
			}
`,
			expected: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
							KMSKeyID: types.String("aws_kms_key.redshift", types.NewTestMetadata()),
						},
						SubnetGroupName: types.String("redshift_subnet", types.NewTestMetadata()),
					},
				},
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    types.NewTestMetadata(),
						Description: types.String("some description", types.NewTestMetadata()),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			fmt.Println(adapted.SecurityGroups[0].Description.Value())
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.Cluster
	}{
		{
			name: "key as string",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			  cluster_identifier = "tf-redshift-cluster"
			  encrypted          = true
			  kms_key_id         = "key-id"
			  cluster_subnet_group_name = "redshift_subnet"
			}
`,
			expected: redshift.Cluster{
				Metadata: types.NewTestMetadata(),
				Encryption: redshift.Encryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("key-id", types.NewTestMetadata()),
				},
				SubnetGroupName: types.String("redshift_subnet", types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `			
			resource "aws_redshift_cluster" "example" {
			}
`,
			expected: redshift.Cluster{
				Metadata: types.NewTestMetadata(),
				Encryption: redshift.Encryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(false, types.NewTestMetadata()),
					KMSKeyID: types.String("", types.NewTestMetadata()),
				},
				SubnetGroupName: types.String("", types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptSecurityGroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  redshift.SecurityGroup
	}{
		{
			name: "defaults",
			terraform: `
resource "" "example" {
}
`,
			expected: redshift.SecurityGroup{
				Metadata:    types.NewTestMetadata(),
				Description: types.String("Managed by Terraform", types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecurityGroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "redshift" {
		enable_key_rotation = true
	}
	
	resource "aws_redshift_cluster" "example" {
	  cluster_identifier = "tf-redshift-cluster"
	  encrypted          = true
	  kms_key_id         = aws_kms_key.redshift.key_id
	  cluster_subnet_group_name = "subnet name"
	}

	resource "aws_redshift_security_group" "default" {
		name = "redshift-sg"
		description = "some description"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.SecurityGroups, 1)
	cluster := adapted.Clusters[0]
	securityGroup := adapted.SecurityGroups[0]

	assert.Equal(t, 6, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, cluster.Encryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, cluster.Encryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 2, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, cluster.SubnetGroupName.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, cluster.SubnetGroupName.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, securityGroup.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, securityGroup.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, securityGroup.Description.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, securityGroup.Description.GetMetadata().Range().GetEndLine())
}
