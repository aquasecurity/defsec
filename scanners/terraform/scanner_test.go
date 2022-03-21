package terraform

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/test/testutil/filesystem"

	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/severity"
)

var alwaysFailRule = rules.Rule{
	Provider:  providers.AWSProvider,
	Service:   "service",
	ShortCode: "abc",
	Severity:  severity.High,
	CustomChecks: rules.CustomChecks{
		Terraform: &rules.TerraformCustomCheck{
			RequiredTypes:  []string{},
			RequiredLabels: []string{},
			Check: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
				results.Add("oh no", resourceBlock)
				return
			},
		},
	},
}

func scanWithOptions(t *testing.T, code string, opt ...Option) rules.Results {
	fs, err := filesystem.New()
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	require.NoError(t, fs.WriteTextFile("project/main.tf", code))
	scanner := New(opt...)
	require.NoError(t, scanner.AddPath(fs.RealPath("project")))
	results, _, err := scanner.Scan()
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
		OptionWithDebugWriter(buffer),
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

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	err = fs.WriteFile("/code/main.tf", []byte(`
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`))
	require.NoError(t, err)

	err = fs.WriteFile("/rules/test.rego", []byte(`
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

`))
	require.NoError(t, err)

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebugWriter(debugLog),
		OptionWithPolicyDirs([]string{fs.RealPath("rules")}),
	)
	if err := scanner.AddPath(fs.RealPath("/code/main.tf")); err != nil {
		t.Error(err)
	}

	results, _, err := scanner.Scan()
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))

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

			fs, err := filesystem.New()
			require.NoError(t, err)
			defer func() { _ = fs.Close() }()

			err = fs.WriteFile("/code/main.tf", []byte(`
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`))
			require.NoError(t, err)

			err = fs.WriteFile("/rules/test.rego", []byte(fmt.Sprintf(`
package %s

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "evil"
	cause := bucket.name
}

`, test.policyNamespace)))
			require.NoError(t, err)

			scanner := New(
				OptionWithPolicyDirs([]string{fs.RealPath("rules")}),
				OptionWithPolicyNamespaces(test.includedNamespaces...),
			)
			if err := scanner.AddPath(fs.RealPath("/code/main.tf")); err != nil {
				t.Error(err)
			}

			results, _, err := scanner.Scan()
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

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	err = fs.WriteFile("/code/main.tf", []byte(`
resource "aws_s3_bucket" "my-bucket" {
	bucket = "evil"
}
`))
	require.NoError(t, err)

	var actual state.State

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		OptionWithDebugWriter(debugLog),
		OptionWithStateFunc(func(s *state.State) {
			require.NotNil(t, s)
			actual = *s
		}),
	)
	if err := scanner.AddPath(fs.RealPath("/code/main.tf")); err != nil {
		t.Error(err)
	}

	_, _, err = scanner.Scan()
	require.NoError(t, err)

	assert.Equal(t, 1, len(actual.AWS.S3.Buckets))

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}

}
