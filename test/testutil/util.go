package testutil

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/terraform/parser"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/scanners/terraform/executor"
	"github.com/aquasecurity/defsec/test/testutil/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ScanHCL(source string, t *testing.T, additionalOptions ...executor.Option) rules.Results {
	modules := CreateModulesFromSource(t, source, ".tf")
	s := executor.New()
	for _, opt := range additionalOptions {
		opt(s)
	}
	executor.OptionStopOnErrors(true)(s)
	res, _, err := s.Execute(modules)
	require.NoError(t, err)
	for _, result := range res {
		if result.Range() == nil {
			t.Errorf("result has no range specified: %#v", result)
		}
	}
	return res
}

func ScanJSON(source string, t *testing.T) rules.Results {
	modules := CreateModulesFromSource(t, source, ".tf.json")
	res, _, _ := executor.New().Execute(modules)
	return res
}

func CreateModulesFromSource(t *testing.T, source string, ext string) terraform.Modules {
	fs, err := filesystem.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fs.Close() }()
	if err := fs.WriteTextFile("test"+ext, source); err != nil {
		t.Fatal(err)
	}
	path := fs.RealPath("test" + ext)
	p := parser.New(parser.OptionStopOnHCLError(true))
	if err := p.ParseDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll()
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func AssertRuleFound(t *testing.T, ruleID string, results rules.Results, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results.GetFailed())
	assert.True(t, found, append([]interface{}{message}, args...)...)
	for _, result := range results.GetFailed() {
		if result.Rule().LongID() == ruleID {
			m := result.Metadata()
			meta := &m
			for meta != nil {
				assert.NotNil(t, meta.Range(), 0)
				assert.Greater(t, meta.Range().GetStartLine(), 0)
				assert.Greater(t, meta.Range().GetEndLine(), 0)
				meta = meta.Parent()
			}
		}
	}
}

func AssertRuleNotFound(t *testing.T, ruleID string, results rules.Results, message string, args ...interface{}) {
	found := ruleIDInResults(ruleID, results.GetFailed())
	assert.False(t, found, append([]interface{}{message}, args...)...)
}

func ruleIDInResults(ruleID string, results rules.Results) bool {
	for _, res := range results {
		if res.Rule().LongID() == ruleID {
			return true
		}
	}
	return false
}
