package terraformplan

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_OptionWithPolicyDirs_OldRegoMetadata(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tfplan.json": `
{"format_version":"1.1","terraform_version":"1.4.6","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"evil","force_destroy":false,"tags":null,"timeouts":null},"sensitive_values":{"cors_rule":[],"grant":[],"lifecycle_rule":[],"logging":[],"object_lock_configuration":[],"replication_configuration":[],"server_side_encryption_configuration":[],"tags_all":{},"versioning":[],"website":[]}}]}},"resource_changes":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"evil","force_destroy":false,"tags":null,"timeouts":null},"after_unknown":{"acceleration_status":true,"acl":true,"arn":true,"bucket_domain_name":true,"bucket_prefix":true,"bucket_regional_domain_name":true,"cors_rule":true,"grant":true,"hosted_zone_id":true,"id":true,"lifecycle_rule":true,"logging":true,"object_lock_configuration":true,"object_lock_enabled":true,"policy":true,"region":true,"replication_configuration":true,"request_payer":true,"server_side_encryption_configuration":true,"tags_all":true,"versioning":true,"website":true,"website_domain":true,"website_endpoint":true},"before_sensitive":false,"after_sensitive":{"cors_rule":[],"grant":[],"lifecycle_rule":[],"logging":[],"object_lock_configuration":[],"replication_configuration":[],"server_side_encryption_configuration":[],"tags_all":{},"versioning":[],"website":[]}}}],"configuration":{"provider_config":{"aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"profile":{"constant_value":"foo-bar-123123123"},"region":{"constant_value":"us-west-1"}}}},"root_module":{"resources":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"evil"}},"schema_version":0}]}}}
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
	"selector": [{"type": "cloud", "subtypes": [{"service": "s3", "provider": "aws"}]}],
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
		options.ScannerWithDebug(debugLog),
		options.ScannerWithPolicyFilesystem(fs),
		options.ScannerWithPolicyDirs("rules"),
		options.ScannerWithRegoOnly(true),
		options.ScannerWithEmbeddedPolicies(false),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]

	assert.Equal(t, "AVD-TEST-0123", failure.Rule().AVDID)

	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     1,
			Content:    "resource \"aws_s3_bucket\" \"my-bucket\" {",
			IsCause:    false,
			FirstCause: false,
			LastCause:  false,
			Annotation: "",
		},
		{
			Number:     2,
			Content:    "\tbucket = \"evil\"",
			IsCause:    true,
			FirstCause: true,
			LastCause:  true,
			Annotation: "",
		},
		{
			Number:     3,
			Content:    "	}",
			IsCause:    false,
			FirstCause: false,
			LastCause:  false,
			Annotation: "",
		},
	}, actualCode.Lines)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}

}

func Test_OptionWithPolicyDirs_WithUserNamespace(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/main.tfplan.json": `
{"format_version":"1.1","terraform_version":"1.4.6","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_name":"registry.terraform.io/hashicorp/aws","schema_version":0,"values":{"bucket":"evil","force_destroy":false,"tags":null,"timeouts":null},"sensitive_values":{"cors_rule":[],"grant":[],"lifecycle_rule":[],"logging":[],"object_lock_configuration":[],"replication_configuration":[],"server_side_encryption_configuration":[],"tags_all":{},"versioning":[],"website":[]}}]}},"resource_changes":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":{"bucket":"evil","force_destroy":false,"tags":null,"timeouts":null},"after_unknown":{"acceleration_status":true,"acl":true,"arn":true,"bucket_domain_name":true,"bucket_prefix":true,"bucket_regional_domain_name":true,"cors_rule":true,"grant":true,"hosted_zone_id":true,"id":true,"lifecycle_rule":true,"logging":true,"object_lock_configuration":true,"object_lock_enabled":true,"policy":true,"region":true,"replication_configuration":true,"request_payer":true,"server_side_encryption_configuration":true,"tags_all":true,"versioning":true,"website":true,"website_domain":true,"website_endpoint":true},"before_sensitive":false,"after_sensitive":{"cors_rule":[],"grant":[],"lifecycle_rule":[],"logging":[],"object_lock_configuration":[],"replication_configuration":[],"server_side_encryption_configuration":[],"tags_all":{},"versioning":[],"website":[]}}}],"configuration":{"provider_config":{"aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"profile":{"constant_value":"foo-bar-123123123"},"region":{"constant_value":"us-west-1"}}}},"root_module":{"resources":[{"address":"aws_s3_bucket.my-bucket","mode":"managed","type":"aws_s3_bucket","name":"my-bucket","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"evil"}},"schema_version":0}]}}}
`,
		"/rules/test.rego": `
# METADATA
# title: Bad buckets are bad
# description: Bad buckets are bad because they are not good.
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   avd_id: AVD-TEST-0123
#   severity: CRITICAL
#   short_code: very-bad-misconfig
#   recommended_action: "Fix the s3 bucket"

package user.foobar.ABC001

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "evil"
	cause := bucket.name
}
`,
	})

	debugLog := bytes.NewBuffer([]byte{})
	scanner := New(
		options.ScannerWithDebug(debugLog),
		options.ScannerWithPolicyFilesystem(fs),
		options.ScannerWithPolicyDirs("rules"),
		options.ScannerWithRegoOnly(true),
		options.ScannerWithPolicyNamespaces("user"),
		options.ScannerWithEmbeddedPolicies(false),
	)

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]

	assert.Equal(t, "AVD-TEST-0123", failure.Rule().AVDID)

	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     1,
			Content:    "resource \"aws_s3_bucket\" \"my-bucket\" {",
			IsCause:    false,
			FirstCause: false,
			LastCause:  false,
			Annotation: "",
		},
		{
			Number:     2,
			Content:    "\tbucket = \"evil\"",
			IsCause:    true,
			FirstCause: true,
			LastCause:  true,
			Annotation: "",
		},
		{
			Number:     3,
			Content:    "	}",
			IsCause:    false,
			FirstCause: false,
			LastCause:  false,
			Annotation: "",
		},
	}, actualCode.Lines)

	if t.Failed() {
		fmt.Printf("Debug logs:\n%s\n", debugLog.String())
	}

}
