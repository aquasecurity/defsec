package main

import (
	"os"

	"github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/types"
)

func main() {

	rulesFS := os.DirFS("internal/rules")

	r := rego.NewScanner(types.SourceCloud)
	if err := r.LoadPolicies(false, rulesFS, []string{"."}, nil); err != nil {
		panic(err)
	}

}
