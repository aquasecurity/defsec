package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/scanners/terraform/executor"

	"github.com/aquasecurity/defsec/parsers/terraform/parser"
	"github.com/aquasecurity/defsec/test/testutil/filesystem"
)

func BenchmarkCalculate(b *testing.B) {
	fs, err := filesystem.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = fs.Close() }()

	createBadBlocks(fs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := parser.New(parser.OptionStopOnHCLError(true))
		if err := p.ParseDirectory(fs.RealPath("/project")); err != nil {
			panic(err)
		}
		modules, _, err := p.EvaluateAll(context.TODO())
		if err != nil {
			panic(err)
		}
		_, _, _ = executor.New().Execute(modules)
	}
}

func createBadBlocks(fs *filesystem.FileSystem) {
	_ = fs.WriteTextFile("/project/main.tf", `
		module "something" {
			source = "../modules/problem"
		}
		`)

	for _, rule := range rules.GetRegistered() {
		if rule.Rule().Terraform == nil {
			continue
		}
		for i, bad := range rule.Rule().Terraform.BadExamples {
			_ = fs.WriteTextFile(fmt.Sprintf("/modules/problem/%s-%d.tf", rule.Rule().LongID(), i), bad)
		}
	}
}
