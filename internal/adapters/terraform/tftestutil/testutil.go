package tftestutil

import (
	"context"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/test/testutil"
)

func CreateModulesFromSource(t *testing.T, source string, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})
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
