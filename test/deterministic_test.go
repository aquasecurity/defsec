package test

import (
	"testing"

	"github.com/aquasecurity/defsec/scanners/terraform/executor"

	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/defsec/test/testutil/filesystem"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/parsers/terraform/parser"
)

func Test_DeterministicResults(t *testing.T) {

	reg := rules.Register(badRule, nil)
	defer rules.Deregister(reg)

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer func() { _ = fs.Close() }()
	require.NoError(t, fs.WriteTextFile("/project/first.tf", `
resource "problem" "uhoh" {
	bad = true
    for_each = other.thing
}
`))
	require.NoError(t, fs.WriteTextFile("/project/second.tf", `
resource "other" "thing" {
    for_each = local.list
}
`))
	require.NoError(t, fs.WriteTextFile("/project/third.tf", `
locals {
    list = {
        a = 1,
        b = 2,
    }
}
`))

	for i := 0; i < 100; i++ {
		p := parser.New(parser.OptionStopOnHCLError(true))
		err := p.ParseDirectory(fs.RealPath("/project"))
		require.NoError(t, err)
		modules, _, err := p.EvaluateAll()
		require.NoError(t, err)
		results, _, _ := executor.New().Execute(modules)
		require.Len(t, results.GetFailed(), 2)
	}
}
