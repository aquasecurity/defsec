package main

import (
	"context"
	"os"

	"github.com/aquasecurity/defsec/pkg/formatters"

	"github.com/aquasecurity/defsec/pkg/scanners/universal"

	"github.com/aquasecurity/defsec/pkg/extrafs"
)

func main() {
	results, err := universal.New(universal.OptionWithDebug(os.Stderr)).ScanFS(context.TODO(), extrafs.OSDir("."), ".")
	if err != nil {
		panic(err)
	}
	if err := formatters.New().AsSARIF().Build().Output(results); err != nil {
		panic(err)
	}
}
