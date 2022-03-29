package test

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/scan"

	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/test/testutil"
)

func createModulesFromSource(t *testing.T, source string, ext string) terraform.Modules {
	fs, _, tidy := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})
	defer tidy()
	p := parser.New(parser.OptionStopOnHCLError(true))
	if err := p.ParseFS(context.TODO(), fs, "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(context.TODO(), fs)
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func scanHCLWithWorkspace(t *testing.T, source string, workspace string) scan.Results {
	return scanHCL(t, source, scanner.OptionWithWorkspaceName(workspace))
}

func scanHCL(t *testing.T, source string, options ...scanner.Option) scan.Results {

	fs, _, tidy := testutil.CreateFS(t, map[string]string{
		"main.tf": source,
	})
	defer tidy()

	s := scanner.New(options...)
	results, err := s.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}

func scanJSON(t *testing.T, source string) scan.Results {

	fs, _, tidy := testutil.CreateFS(t, map[string]string{
		"main.tf.json": source,
	})
	defer tidy()

	s := scanner.New()
	results, _, err := s.ScanFSWithMetrics(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}
