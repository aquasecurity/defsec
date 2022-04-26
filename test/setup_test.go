package test

import (
	"context"
	"sync"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/scan"

	cfScanner "github.com/aquasecurity/defsec/pkg/scanners/cloudformation"
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

var terraformScanner *tfScanner.Scanner
var tfLock sync.RWMutex
var cloudformationScanner *cfScanner.Scanner
var cfLock sync.RWMutex

func scanHCL(t *testing.T, source string, options ...options.ScannerOption) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.tf": source,
	})

	tfLock.RLock()
	localScanner := terraformScanner
	tfLock.RUnlock()
	if localScanner == nil || len(options) > 0 {
		tfLock.RLock()
		localScanner = tfScanner.New(options...)
		tfLock.RUnlock()
		if len(options) == 0 {
			tfLock.Lock()
			terraformScanner = localScanner
			tfLock.Unlock()
		}
	}
	tfLock.RLock()
	results, err := localScanner.ScanFS(context.TODO(), fs, ".")
	tfLock.RUnlock()
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

func scanCF(t *testing.T, source string, options ...options.ScannerOption) scan.Results {

	fs := testutil.CreateFS(t, map[string]string{
		"main.yaml": source,
	})

	cfLock.RLock()
	localScanner := cloudformationScanner
	cfLock.RUnlock()
	if localScanner == nil || len(options) > 0 {
		cfLock.RLock()
		localScanner = cfScanner.New(options...)
		cfLock.RUnlock()
		if len(options) == 0 {
			cfLock.Lock()
			cloudformationScanner = localScanner
			cfLock.Unlock()
		}
	}
	cfLock.RLock()
	results, err := localScanner.ScanFS(context.TODO(), fs, ".")
	cfLock.RUnlock()
	require.NoError(t, err)
	return results
}
