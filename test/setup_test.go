package test

import (
	"context"
	"testing"

	cfScanner "github.com/aquasecurity/defsec/pkg/scanners/aws/cloudformation"
	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/scan"

	tfScanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/test/testutil"
)

func createModulesFromSource(t *testing.T, source string, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func scanHCLWithWorkspace(t *testing.T, source string, workspace string) scan.Results {
	return scanHCL(t, source, tfScanner.ScannerWithWorkspaceName(workspace))
}

func scanHCL(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": source,
	})

	localScanner := tfScanner.New(append(opts, options.ScannerWithEmbeddedPolicies(false))...)
	results, err := localScanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}

func scanJSON(t *testing.T, source string) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf.json": source,
	})

	s := tfScanner.New()
	results, _, err := s.ScanFSWithMetrics(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}

func scanCF(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.yaml": source,
	})

	localScanner := cfScanner.New(append(opts, options.ScannerWithEmbeddedPolicies(false))...)
	results, err := localScanner.ScanFS(context.TODO(), fs, ".")
	require.NoError(t, err)
	return results
}
