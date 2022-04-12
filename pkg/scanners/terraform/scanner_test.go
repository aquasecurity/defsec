package terraform

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

var alwaysFailRule = scan.Rule{
	Provider:  providers.AWSProvider,
	Service:   "service",
	ShortCode: "abc",
	Severity:  severity.High,
	CustomChecks: scan.CustomChecks{
		Terraform: &scan.TerraformCustomCheck{
			RequiredTypes:  []string{},
			RequiredLabels: []string{},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results scan.Results) {
				results.Add("oh no", resourceBlock)
				return
			},
		},
	},
}

func scanWithOptions(t *testing.T, code string, opt ...Option) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"project/main.tf": code,
	})

	scanner := New(opt...)
	results, _, err := scanner.ScanFSWithMetrics(context.TODO(), fs, "project")
	require.NoError(t, err)
	return results
}

func Test_OptionWithAlternativeIDProvider(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	options := []Option{
		OptionWithAlternativeIDProvider(func(s string) []string {
			return []string{"something", "altid", "blah"}
		}),
	}
	results := scanWithOptions(t, `
//tfsec:ignore:altid
resource "something" "else" {}
`, options...)
	require.Len(t, results.GetFailed(), 0)
	require.Len(t, results.GetIgnored(), 1)

}

func Test_OptionWithSeverityOverrides(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	options := []Option{
		OptionWithSeverityOverrides(map[string]string{"aws-service-abc": "LOW"}),
	}
	results := scanWithOptions(t, `
resource "something" "else" {}
`, options...)
	require.Len(t, results.GetFailed(), 1)
	assert.Equal(t, severity.Low, results.GetFailed()[0].Severity())
}

func Test_OptionWithDebugWriter(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	buffer := bytes.NewBuffer([]byte{})

	options := []Option{
		OptionWithDebug(buffer),
	}
	_ = scanWithOptions(t, `
resource "something" "else" {}
`, options...)
	require.Greater(t, buffer.Len(), 0)
}

func Test_OptionNoIgnores(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	options := []Option{
		OptionNoIgnores(),
	}
	results := scanWithOptions(t, `
//tfsec:ignore:aws-service-abc
resource "something" "else" {}
`, options...)
	require.Len(t, results.GetFailed(), 1)
	require.Len(t, results.GetIgnored(), 0)

}

func Test_OptionExcludeRules(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	options := []Option{
		OptionExcludeRules([]string{"aws-service-abc"}),
	}
	results := scanWithOptions(t, `
resource "something" "else" {}
`, options...)
	require.Len(t, results.GetFailed(), 0)
	require.Len(t, results.GetIgnored(), 1)

}

func Test_OptionIncludeRules(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	options := []Option{
		OptionIncludeRules([]string{"this-only"}),
	}
	results := scanWithOptions(t, `
resource "something" "else" {}
`, options...)
	require.Len(t, results.GetFailed(), 0)
	require.Len(t, results.GetIgnored(), 1)

}

func Test_OptionWithMinimumSeverity(t *testing.T) {
	reg := rules.Register(alwaysFailRule, nil)
	defer rules.Deregister(reg)

	options := []Option{
		OptionWithMinimumSeverity(severity.Critical),
	}
	results := scanWithOptions(t, `
resource "something" "else" {}
`, options...)
	require.Len(t, results.GetFailed(), 0)
	require.Len(t, results.GetIgnored(), 1)

}

func Test_OptionWithPolicyDirs(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`,
		"/rules/test.rego": `
package defsec.abcdefg

__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec"}],
}

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "evil"
	cause := bucket.name
}
`,
	})

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebug(debugLog),
		OptionWithPolicyDirs("rules"),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	var found bool
	for _, result := range results.GetFailed() {
		if result.Rule().AVDID == "AVD-TEST-0123" {
			found = true
			break
		}
	}
	assert.True(t, found)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}

}

func Test_OptionWithPolicyNamespaces(t *testing.T) {

	tests := []struct {
		includedNamespaces []string
		policyNamespace    string
		wantFailure        bool
	}{
		{
			includedNamespaces: nil,
			policyNamespace:    "blah",
			wantFailure:        false,
		},
		{
			includedNamespaces: nil,
			policyNamespace:    "appshield.something",
			wantFailure:        true,
		},
		{
			includedNamespaces: nil,
			policyNamespace:    "defsec.blah",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{"user"},
			policyNamespace:    "users",
			wantFailure:        false,
		},
		{
			includedNamespaces: []string{"users"},
			policyNamespace:    "something.users",
			wantFailure:        false,
		},
		{
			includedNamespaces: []string{"users"},
			policyNamespace:    "users",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{"users"},
			policyNamespace:    "users.my_rule",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{"a", "users", "b"},
			policyNamespace:    "users",
			wantFailure:        true,
		},
		{
			includedNamespaces: []string{"user"},
			policyNamespace:    "defsec",
			wantFailure:        true,
		},
	}

	for i, test := range tests {

		t.Run(strconv.Itoa(i), func(t *testing.T) {

			fs := testutil.CreateFS(t, map[string]string{
				"/code/main.tf": `
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`,
				"/rules/test.rego": fmt.Sprintf(`
				package %s

				deny[cause] {
				bucket := input.aws.s3.buckets[_]
				bucket.name.value == "evil"
				cause := bucket.name
				}

				`, test.policyNamespace),
			})

			scanner := New(
				OptionWithPolicyDirs("rules"),
				OptionWithPolicyNamespaces(test.includedNamespaces...),
			)

			results, _, err := scanner.ScanFSWithMetrics(context.TODO(), fs, "code")
			require.NoError(t, err)

			var found bool
			for _, result := range results.GetFailed() {
				if result.RegoNamespace() == test.policyNamespace && result.RegoRule() == "deny" {
					found = true
					break
				}
			}
			assert.Equal(t, test.wantFailure, found)

		})
	}

}

func Test_OptionWithStateFunc(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"code/main.tf": `
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`,
	})

	var actual state.State

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebug(debugLog),
		OptionWithStateFunc(func(s *state.State) {
			require.NotNil(t, s)
			actual = *s
		}),
	)

	_, _, err := scanner.ScanFSWithMetrics(context.TODO(), fs, "code")
	require.NoError(t, err)

	assert.Equal(t, 1, len(actual.AWS.S3.Buckets))

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}

}

func Test_OptionWithRegoOnly(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`,
		"/rules/test.rego": `
package defsec.abcdefg

__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec"}],
}

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "evil"
	cause := bucket.name
}
`,
	})

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebug(debugLog),
		OptionWithPolicyDirs("rules"),
		OptionWithRegoOnly(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "AVD-TEST-0123", results[0].Rule().AVDID)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}
}

func Test_OptionWithRegoOnly_CodeHighlighting(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`,
		"/rules/test.rego": `
package defsec.abcdefg

import data.lib.defsec

__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec"}],
}

deny[res] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "evil"
	res := defsec.result("oh no", bucket.name)
}
`,
	})

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebug(debugLog),
		OptionWithPolicyDirs("rules"),
		OptionWithRegoOnly(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "AVD-TEST-0123", results[0].Rule().AVDID)
	assert.NotNil(t, results[0].Metadata().Range().GetFS())

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}
}

func Test_IAMPolicyRego(t *testing.T) {
	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tf": `
resource "aws_sqs_queue_policy" "bad_example" {
   queue_url = aws_sqs_queue.q.id

   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "*"
     }
   ]
 }
 POLICY
 }`,
		"/rules/test.rego": `
package defsec.abcdefg

import data.lib.defsec

__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "defsec"}],
}

deny[res] {
	queue := input.aws.sqs.queues[_]
	policy := queue.policies[_]
	statement := policy.document.value.Statement[_]
	action := statement.Action[_]
	action == "*"
	res := defsec.result("SQS Policy contains wildcard in action", policy.document)
}
`,
	})

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebug(debugLog),
		OptionWithPolicyDirs("rules"),
		OptionWithRegoOnly(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "AVD-TEST-0123", results[0].Rule().AVDID)
	assert.NotNil(t, results[0].Metadata().Range().GetFS())

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}
}
