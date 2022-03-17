package dockerfile

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/defsec/rules"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/defsec/test/testutil/filesystem"
	"github.com/stretchr/testify/require"
)

func Test_BasicScan(t *testing.T) {

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()

	require.NoError(t, fs.WriteTextFile("/code/Dockerfile", `FROM ubuntu

USER root
`))

	require.NoError(t, fs.WriteTextFile("/rules/rule.rego", `package appshield.dockerfile.DS006

__rego_metadata__ := {
	"id": "DS006",
	"avd_id": "AVD-DS-0006",
	"title": "COPY '--from' referring to the current image",
	"short_code": "no-self-referencing-copy-from",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
	"recommended_actions": "Change the '--from' so that it will not refer to itself",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	res := {
		"msg": "oh no",
		"filepath": "Dockerfile",
		"startline": 1,
		"endline": 2,
	}
}

`))

	scanner := NewScanner(OptionWithPolicyDirs(fs.RealPath("/rules")))
	require.NoError(t, scanner.AddPath(fs.RealPath("/code/Dockerfile")))

	results, err := scanner.Scan(context.TODO())
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, rules.Rule{
		AVDID:       "AVD-DS-0006",
		LegacyID:    "DS006",
		ShortCode:   "no-self-referencing-copy-from",
		Summary:     "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
		Explanation: "",
		Impact:      "",
		Resolution:  "Change the '--from' so that it will not refer to itself",
		Provider:    "kubernetes",
		Service:     "general",
		Links: []string{
			"https://docs.docker.com/develop/develop-images/multistage-build/",
		},
		Severity:    severity.Critical,
		RegoPackage: "data.appshield.dockerfile.DS006",
	}, results.GetFailed()[0].Rule())
}
