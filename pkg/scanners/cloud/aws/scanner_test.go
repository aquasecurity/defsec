package aws

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers/aws"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
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

func Test_checkPolicyIsApplicable(t *testing.T) {
	t.Run("single cloud", func(t *testing.T) {
		srcFS := testutil.CreateFS(t, map[string]string{
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
		})
		scanner := New(
			options.ScannerWithEmbeddedPolicies(false),
			options.ScannerWithPolicyFilesystem(srcFS),
			options.ScannerWithRegoOnly(true),
			options.ScannerWithPolicyDirs("policies/"))

		st := state.State{AWS: aws.AWS{
			RDS: rds.RDS{
				Instances: []rds.Instance{
					{Metadata: defsecTypes.Metadata{},
						PublicAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			// note: there is no CloudTrail resource in our AWS state (so we expect no results for it)
		}}

		results, err := scanner.Scan(context.TODO(), &st)
		require.NoError(t, err)
		require.Equal(t, 1, len(results))
		require.Equal(t, "RDS Publicly Accessible", results.GetFailed()[0].Rule().Summary)
	})

	t.Run("multi cloud with similarly named services", func(t *testing.T) {
		srcFS := testutil.CreateFS(t, map[string]string{
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
		})
		scanner := New(
			options.ScannerWithEmbeddedPolicies(false),
			options.ScannerWithPolicyFilesystem(srcFS),
			options.ScannerWithRegoOnly(true),
			options.ScannerWithPolicyDirs("policies/"))

		st := state.State{AWS: aws.AWS{
			IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{MinimumLength: defsecTypes.Int(1, defsecTypes.NewTestMetadata())},
			},
			// note: there is no Azure IAM in our cloud state (so we expect no results for it)
		}}

		results, err := scanner.Scan(context.TODO(), &st)
		require.NoError(t, err)
		require.Equal(t, 1, len(results))
		require.Equal(t, "AWS IAM Policy", results.GetFailed()[0].Rule().Summary)
	})
}
