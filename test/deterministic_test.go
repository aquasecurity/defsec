package test

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/executor"

	"github.com/aquasecurity/defsec/test/testutil"

	"github.com/stretchr/testify/require"
)

func Test_DeterministicResults(t *testing.T) {

	reg := rules.Register(badRule, nil)
	defer rules.Deregister(reg)

	fs, _, tidy := testutil.CreateFS(t, map[string]string{
		"first.tf": `
resource "problem" "uhoh" {
	bad = true
	for_each = other.thing
}
		`,
		"second.tf": `
resource "other" "thing" {
	for_each = local.list
}
		`,
		"third.tf": `
locals {
	list = {
		a = 1,
		b = 2,
	}
}
		`,
	})
	defer tidy()

	for i := 0; i < 100; i++ {
		p := parser.New(parser.OptionStopOnHCLError(true))
		err := p.ParseFS(context.TODO(), fs, ".")
		require.NoError(t, err)
		modules, _, err := p.EvaluateAll(context.TODO(), fs)
		require.NoError(t, err)
		results, _, _ := executor.New().Execute(modules)
		require.Len(t, results.GetFailed(), 2)
	}
}
