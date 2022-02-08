package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/appshield/tools/rego"
)

func main() {
	var failure bool
	regoFiles, err := rego.GetAllNonTestRegoFiles()
	if err != nil {
		fail("failed to get the rego files. %v", err)
	}

	fmt.Printf("\nRunning metadata linter against %d policies\n\n", len(regoFiles))
	for _, regoMeta := range regoFiles {
		if valid, failures := regoMeta.Validate(); !valid {
			failure = true
			failureString := strings.Join(failures, "\n - ")
			fmt.Printf("Policy '%s' has invalid metadata: %s\n", regoMeta.Name, failureString)
			fmt.Println()
		}

		if !regoMeta.HasDocsMarkdown() {
			failure = true
			fmt.Printf(`Policy '%s' has no avd_docs, run "make generate_missing_docs"
`, regoMeta.Name)
		}
	}
	if failure {
		fail("\nIssues were found, failing lint\n")
	}
	fmt.Println("No issues found")
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}
