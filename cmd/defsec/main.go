package main

import (
	"context"
	"os"

	"github.com/aquasecurity/defsec/pkg/formatters"

	"github.com/aquasecurity/defsec/pkg/scanners/universal"

	"github.com/aquasecurity/defsec/pkg/extrafs"
)

func main() {
	fsys := extrafs.OSDir(".")
	results, err := universal.New(universal.OptionWithDebug(os.Stderr)).ScanFS(context.TODO(), fsys, ".")
	if err != nil {
		panic(err)
	}
	if err := formatters.New().AsSARIF().Build().Output(fsys, results); err != nil {
		panic(err)
	}
}
