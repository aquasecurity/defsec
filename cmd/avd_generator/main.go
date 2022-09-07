package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/framework"
	_ "github.com/aquasecurity/defsec/pkg/rego"
	registered "github.com/aquasecurity/defsec/pkg/rules"
)

func main() {

	var generateCount int

	for _, metadata := range registered.GetRegistered(framework.ALL) {
		writeDocsFile(metadata)
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in avd_docs\n", generateCount)
}

func writeDocsFile(meta rules.RegisteredRule) {

	tmpl, err := template.New("defsec").Parse(docsMarkdownTemplate)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}

	docpath := filepath.Join("avd_docs",
		strings.ToLower(meta.Rule().Provider.ConstName()),
		strings.ToLower(strings.ReplaceAll(meta.Rule().Service, "-", "")),
		meta.Rule().AVDID,
	)

	if err := os.MkdirAll(docpath, os.ModePerm); err != nil {
		panic(err)
	}

	file, err := os.Create(filepath.Join(docpath, "docs.md"))
	if err != nil {
		fail("error occurred creating the docs file for %s", docpath)
	}

	if err := tmpl.Execute(file, meta.Rule()); err != nil {
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating docs file for policy %s\n", meta.Rule().AVDID)

	if meta.Rule().Terraform != nil {
		tmpl, err := template.New("terraform").Parse(terraformMarkdownTemplate)
		if err != nil {
			fail("error occurred creating the template %v\n", err)
		}
		file, err := os.Create(filepath.Join(docpath, "Terraform.md"))
		if err != nil {
			fail("error occurred creating the Terraform file for %s", docpath)
		}

		if err := tmpl.Execute(file, meta.Rule()); err != nil {
			fail("error occurred generating the document %v", err)
		}
		fmt.Printf("Generating Terraform file for policy %s\n", meta.Rule().AVDID)
	}

	if meta.Rule().CloudFormation != nil {
		tmpl, err := template.New("cloudformation").Parse(cloudformationMarkdownTemplate)
		if err != nil {
			fail("error occurred creating the template %v\n", err)
		}
		file, err := os.Create(filepath.Join(docpath, "CloudFormation.md"))
		if err != nil {
			fail("error occurred creating the CloudFormation file for %s", docpath)
		}

		if err := tmpl.Execute(file, meta.Rule()); err != nil {
			fail("error occurred generating the document %v", err)
		}
		fmt.Printf("Generating CloudFormation file for policy %s\n", meta.Rule().AVDID)
	}
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

var docsMarkdownTemplate = `
{{ .Explanation }}

### Impact
{{ if .Impact }}{{ .Impact }}{{ else }}<!-- Add Impact here -->{{ end }}

<!-- DO NOT CHANGE -->
{{ ` + "`{{ " + `remediationActions ` + "`}}" + `}}

{{ if .Links }}### Links{{ range .Links }}
- {{ . }}
{{ end}}
{{ end }}
`

var terraformMarkdownTemplate = `
{{ .Resolution }}

{{ if .Terraform.GoodExamples }}{{ range .Terraform.GoodExamples }}` + "```hcl" + `{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .Terraform.Links }}#### Remediation Links{{ range .Terraform.Links }}
 - {{ . }}
{{ end}}{{ end }}
`

var cloudformationMarkdownTemplate = `
{{ .Resolution }}

{{ if .CloudFormation.GoodExamples }}{{ range .CloudFormation.GoodExamples }}` + "```yaml" + `{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .CloudFormation.Links }}#### Remediation Links{{ range .CloudFormation.Links }}
 - {{ . }}
{{ end}}{{ end }}
`
