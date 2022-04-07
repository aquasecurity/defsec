package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/defsec/internal/rules"
	registered "github.com/aquasecurity/defsec/pkg/rules"
)

func main() {

	var generateCount int

	for _, metadata := range registered.GetRegistered() {
		writeDocsFile(metadata)
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in avd_docs\n", generateCount)
}

func writeDocsFile(meta rules.RegisteredRule) {

	tmpl, err := template.New("appshield").Parse(docsMarkdownTemplate)
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
		fail("error occurred creating the file for %s", docpath)
	}

	if err := tmpl.Execute(file, meta.Rule()); err != nil {
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating file for policy %s\n", meta.Rule().AVDID)
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
