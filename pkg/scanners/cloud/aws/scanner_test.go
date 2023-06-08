package aws

import (
	"context"
	"io/fs"
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/azure"
	"github.com/aquasecurity/defsec/pkg/providers/azure/authorization"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_GetRegisteredRules(t *testing.T) {
	testCases := []struct {
		name    string
		scanner *Scanner
	}{
		{
			name: "get framework rules",
			scanner: &Scanner{
				frameworks: []framework.Framework{framework.CIS_AWS_1_2},
			},
		},
		{
			name: "get spec rules",
			scanner: &Scanner{
				spec: "awscis1.2",
			},
		},
		{
			name: "invalid spec",
			scanner: &Scanner{
				spec: "invalid spec",
				// we still expect default rules to work
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, i := range tc.scanner.getRegisteredRules() {
				if _, ok := i.Rule().Frameworks[framework.CIS_AWS_1_2]; !ok {
					assert.FailNow(t, "unexpected rule found: ", i.Rule().AVDID, tc.name)
				}
			}
		})
	}
}

func Test_AWSInputSelectors(t *testing.T) {
	testCases := []struct {
		name            string
		srcFS           fs.FS
		dataFS          fs.FS
		state           state.State
		expectedResults struct {
			totalResults int
			summaries    []string
		}
	}{
		{
			name: "selector is not defined",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   input:
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# custom:
#   input:
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "selector is empty",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   input:
#     selector:
        
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# custom:
#   input:
#     selector:
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "selector without subtype",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   input:
#     selector:
#     - type: cloud
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "conflicting selectors",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   provider: aws
#   service: rds
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: ec2
package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
			}),

			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 0},
		},
		{
			name: "selector is defined with empty subtype",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:

package builtin.aws.rds.aws0999

deny[res] {
	res := true
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:
package builtin.aws.cloudtrail.aws0888

deny[res] {
	res := true
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 2, summaries: []string{"RDS Publicly Accessible", "CloudTrail Bucket Delete Policy"}},
		},
		{
			name: "single cloud, single selector",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0999
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: rds
package builtin.aws.rds.aws0999

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}
`,
				"policies/cloudtrail_policy.rego": `# METADATA
# title: "CloudTrail Bucket Delete Policy"
# description: "Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token"
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete
# custom:
#   avd_id: AVD-AWS-0888
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: bucket_delete
#   recommended_action: "Enable MFA delete on the CloudTrail bucket"
#   input:
#     selector:
#     - type: cloud
#       subtypes: 
#         - provider: aws 
#           service: cloudtrail
package builtin.aws.cloudtrail.aws0888

deny[res] {
	trail := input.aws.cloudtrail.trails[_]
	trail.bucketname.value != ""
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == trail.bucketname.value
    not bucket.versioning.mfadelete.value
	res := result.new("Bucket has MFA delete disabled", bucket.name)
}
`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 1, summaries: []string{"RDS Publicly Accessible"}},
		},
		{
			name: "multi cloud, single selector, same named service",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/azure_iam_policy.rego": `# METADATA
# title: "Azure IAM Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: azure 
#           service: iam 
package builtin.azure.iam.iam1234

deny[res] {
	res := true
}
`,
				"policies/aws_iam_policy.rego": `# METADATA
# title: "AWS IAM Policy"
# custom:
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws 
#           service: iam 
package builtin.aws.iam.iam5678

deny[res] {
	res := true
}
`,
			}),
			state: state.State{
				AWS: aws.AWS{
					IAM: iam.IAM{
						PasswordPolicy: iam.PasswordPolicy{
							MinimumLength: defsecTypes.Int(1, defsecTypes.NewTestMetadata()),
						}},
				},
				Azure: azure.Azure{
					Authorization: authorization.Authorization{
						RoleDefinitions: []authorization.RoleDefinition{{
							Metadata: defsecTypes.NewTestMetadata(),
							Permissions: []authorization.Permission{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									Actions: []defsecTypes.StringValue{
										defsecTypes.String("*", defsecTypes.NewTestMetadata()),
									},
								},
							},
							AssignableScopes: []defsecTypes.StringValue{
								defsecTypes.StringUnresolvable(defsecTypes.NewTestMetadata()),
							}},
						}},
				},
				// note: there is no Azure IAM in our cloud state (so we expect no results for it)
			},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 1, summaries: []string{"AWS IAM Policy"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			scanner := New(
				options.ScannerWithEmbeddedPolicies(false),
				options.ScannerWithPolicyFilesystem(tc.srcFS),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithPolicyDirs("policies/"))

			results, err := scanner.Scan(context.TODO(), &tc.state)
			require.NoError(t, err, tc.name)
			require.Equal(t, tc.expectedResults.totalResults, len(results), tc.name)
			for i := range results.GetFailed() {
				require.Contains(t, tc.expectedResults.summaries, results.GetFailed()[i].Rule().Summary, tc.name)
			}
		})
	}
}

func Test_AWSInputSelectorsWithConfigData(t *testing.T) {
	testCases := []struct {
		name            string
		srcFS           fs.FS
		dataFS          fs.FS
		state           state.State
		expectedResults struct {
			totalResults int
			summaries    []string
		}
	}{
		{
			name: "single cloud, single selector with config data",
			srcFS: testutil.CreateFS(t, map[string]string{
				"policies/rds_policy.rego": `# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema.input
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0999
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance'"
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - provider: aws
#           service: rds
package builtin.aws.rds.aws0999
import data.settings.DS0999.ignore_deletion_protection

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	not ignore_deletion_protection
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}
`,
			}),
			dataFS: testutil.CreateFS(t, map[string]string{
				"config-data/data.json": `{
    "settings": {
		"DS0999": {
			"ignore_deletion_protection": false
		}
    }
}

`,
			}),
			state: state.State{AWS: aws.AWS{
				RDS: rds.RDS{
					Instances: []rds.Instance{
						{Metadata: defsecTypes.Metadata{},
							PublicAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
				// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
			}},
			expectedResults: struct {
				totalResults int
				summaries    []string
			}{totalResults: 1, summaries: []string{"RDS Publicly Accessible"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			scanner := New(
				options.ScannerWithEmbeddedPolicies(false),
				options.ScannerWithPolicyFilesystem(tc.srcFS),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithPolicyDirs("policies/"),
				options.ScannerWithDataFilesystem(tc.dataFS),
				options.ScannerWithDataDirs("config-data/"))

			results, err := scanner.Scan(context.TODO(), &tc.state)
			require.NoError(t, err, tc.name)
			require.Equal(t, tc.expectedResults.totalResults, len(results), tc.name)
			for i := range results.GetFailed() {
				require.Contains(t, tc.expectedResults.summaries, results.GetFailed()[i].Rule().Summary, tc.name)
			}
		})
	}
}
