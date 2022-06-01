package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/defsec/pkg/formatters"

	"github.com/aquasecurity/defsec/pkg/scanners/universal"

	"github.com/aquasecurity/defsec/pkg/extrafs"
)

func main() {
	dir := os.Args[1]
	abs, err := filepath.Abs(dir)
	if err != nil {
		panic(err)
	}
	fsys := extrafs.OSDir(abs)
	results, err := universal.New(options.ScannerWithDebug(os.Stderr), options.ScannerWithEmbeddedPolicies(true)).ScanFS(context.TODO(), fsys, ".")
	if err != nil {
		panic(err)
	}
	if err := formatters.New().WithBaseDir(abs).AsSARIF().Build().Output(results); err != nil {
		panic(err)
	}
}
