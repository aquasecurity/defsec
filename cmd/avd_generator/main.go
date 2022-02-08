package main

import (
	"fmt"
	"os"
	"text/template"

	"github.com/aquasecurity/defsec/cmd/rego"
)

func main() {
	regoFiles, err := rego.GetAllNonTestRegoFiles()
	if err != nil {
		fail("failed to get the rego files. %v", err)
	}

	var generateCount int
	for _, regoMeta := range regoFiles {

		if _, err := os.Stat(regoMeta.DocsFilePath()); err == nil {
			continue
		}

		if err := os.MkdirAll(regoMeta.DocsFolder(), 0755); err != nil {
			fail("an error occurred creating the docs folder for %s. %v", regoMeta.DocsFolder(), err)
		}

		writeDocsFile(regoMeta)
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in avd_docs\n", generateCount)
}

func writeDocsFile(meta *rego.RegoMetadata) {

	tmpl, err := template.New("appshield").Parse(docsMarkdownTemplate)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}

	file, err := os.Create(meta.DocsFilePath())
	if err != nil {
		fail("error occurred creating the file for %s", meta.DocsFilePath())
	}

	if err := tmpl.Execute(file, meta); err != nil {
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating file for policy %s\n", meta.Name)
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

var docsMarkdownTemplate = `
### {{ .Title }}
{{ .Description }}

### Impact
<!-- Add Impact here -->

<!-- DO NOT CHANGE -->
{{ ` + "`{{ " + `remediationActions ` + "`}}" + `}}

{{ if .Url }}### Links
- {{ .Url }}
{{ end }}
`
