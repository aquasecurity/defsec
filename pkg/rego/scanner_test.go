package rego

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_RegoScanning_Deny(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.False(t, results.GetFailed()[0].IsWarning())
}

func Test_RegoScanning_Warn(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

warn {
    input.evil
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	require.Equal(t, 0, len(results.GetPassed()))
	require.Equal(t, 0, len(results.GetIgnored()))

	assert.True(t, results.GetFailed()[0].IsWarning())
}

func Test_RegoScanning_Allow(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": false,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	require.Equal(t, 1, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "/evil.lol", results.GetPassed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_Namespace_Exception(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
		"policies/exceptions.rego": `
package namespace.exceptions

import data.namespaces

exception[ns] {
    ns := data.namespaces[_]
    startswith(ns, "defsec")
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 1, len(results.GetIgnored()))

}

func Test_RegoScanning_Namespace_Exception_WithoutMatch(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`, "policies/something.rego": `
package appshield.test

deny_something {
    input.something
}
`,
		"policies/exceptions.rego": `
package namespace.exceptions

import data.namespaces

exception[ns] {
    ns := data.namespaces[_]
    startswith(ns, "appshield")
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 1, len(results.GetIgnored()))

}

func Test_RegoScanning_Rule_Exception(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test
deny_evil {
    input.evil
}
`,
		"policies/exceptions.rego": `
package defsec.test

exception[rules] {
    rules := ["evil"]
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 1, len(results.GetIgnored()))
}

func Test_RegoScanning_Rule_Exception_WithoutMatch(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test
deny_evil {
    input.evil
}
`,
		"policies/exceptions.rego": `
package defsec.test

exception[rules] {
    rules := ["good"]
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_WithRuntimeValues(t *testing.T) {

	_ = os.Setenv("DEFSEC_RUNTIME_VAL", "AOK")

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny_evil {
    output := opa.runtime()
	output.env.DEFSEC_RUNTIME_VAL == "AOK"
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_WithDenyMessage(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny[msg] {
    input.evil
	msg := "oh no"
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
}

func Test_RegoScanning_WithDenyMetadata_ImpliedPath(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny[res] {
    input.evil
	res := {
		"msg": "oh no",
		"startline": 123,
		"endline": 456,
	}
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/evil.lol", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.Equal(t, 123, results.GetFailed()[0].Metadata().Range().GetStartLine())
	assert.Equal(t, 456, results.GetFailed()[0].Metadata().Range().GetEndLine())

}

func Test_RegoScanning_WithDenyMetadata_PersistedPath(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny[res] {
    input.evil
	res := {
		"msg": "oh no",
		"startline": 123,
		"endline": 456,
		"filepath": "/blah.txt",
	}
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Equal(t, "oh no", results.GetFailed()[0].Description())
	assert.Equal(t, "/blah.txt", results.GetFailed()[0].Metadata().Range().GetFilename())
	assert.Equal(t, 123, results.GetFailed()[0].Metadata().Range().GetStartLine())
	assert.Equal(t, 456, results.GetFailed()[0].Metadata().Range().GetEndLine())

}

func Test_RegoScanning_WithStaticMetadata(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_metadata__ := {
	"id": "AA001",
	"avd_id": "AVD-XX-9999",
	"title": "This is a title",
	"short_code": "short-code",
	"severity": "LOW",
	"type": "Dockerfile Security Check",
	"description": "This is a description",
	"recommended_actions": "This is a recommendation",
	"url": "https://google.com",
}

deny[res] {
    input.evil
	res := {
		"msg": "oh no",
		"startline": 123,
		"endline": 456,
		"filepath": "/blah.txt",
	}
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	require.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	failure := results.GetFailed()[0]

	assert.Equal(t, "oh no", failure.Description())
	assert.Equal(t, "/blah.txt", failure.Metadata().Range().GetFilename())
	assert.Equal(t, 123, failure.Metadata().Range().GetStartLine())
	assert.Equal(t, 456, failure.Metadata().Range().GetEndLine())
	assert.Equal(t, "AVD-XX-9999", failure.Rule().AVDID)
	assert.Equal(t, "AA001", failure.Rule().LegacyID)
	assert.Equal(t, "This is a title", failure.Rule().Summary)
	assert.Equal(t, severity.Low, failure.Rule().Severity)
	assert.Equal(t, "This is a recommendation", failure.Rule().Resolution)
	assert.Equal(t, "https://google.com", failure.Rule().Links[0])

}

func Test_RegoScanning_WithMatchingInputSelector(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_input__ := {
	"selector": [{"type": "testing"}],
}

deny {
    input.evil
}

`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "testing",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_WithNonMatchingInputSelector(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

__rego_input__ := {
	"selector": [{"type": "testing"}],
}

deny {
    input.evil
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "not-a-match",
	})
	require.NoError(t, err)

	assert.Equal(t, 0, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))
}

func Test_RegoScanning_NoTracingByDefault(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner()
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Len(t, results.GetFailed()[0].Traces(), 0)
}

func Test_RegoScanning_GlobalTracingEnabled(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	traceBuffer := bytes.NewBuffer([]byte{})

	scanner := NewScanner(options.ScannerWithTrace(traceBuffer))
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Len(t, results.GetFailed()[0].Traces(), 0)
	assert.Greater(t, len(traceBuffer.Bytes()), 0)
}

func Test_RegoScanning_PerResultTracingEnabled(t *testing.T) {

	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/test.rego": `
package defsec.test

deny {
    input.evil
}
`,
	})

	scanner := NewScanner(options.ScannerWithPerResultTracing(true))
	require.NoError(
		t,
		scanner.LoadPolicies(false, srcFS, []string{"policies"}, nil),
	)

	results, err := scanner.ScanInput(context.TODO(), Input{
		Path: "/evil.lol",
		Contents: map[string]interface{}{
			"evil": true,
		},
		Type: "???",
	})
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
	assert.Equal(t, 0, len(results.GetPassed()))
	assert.Equal(t, 0, len(results.GetIgnored()))

	assert.Greater(t, len(results.GetFailed()[0].Traces()), 0)
}
