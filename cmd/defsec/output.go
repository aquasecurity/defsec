package main

import (
	"fmt"
	"io"

	"github.com/aquasecurity/defsec/pkg/formatters"
	"github.com/aquasecurity/defsec/pkg/scan"
)

func outputResults(w io.Writer, baseDir string, results scan.Results) error {

	factory := formatters.
		New().
		WithWriter(w).
		WithBaseDir(baseDir)

	switch flagFormat {
	case "csv":
		factory.AsCSV()
	case "json":
		factory.AsJSON()
	case "junit":
		factory.AsJUnit()
	case "sarif":
		factory.AsSARIF()
	case "simple":
		factory.AsSimple()
	case "checkstyle":
		factory.AsCheckStyle()
	default:
		return fmt.Errorf("unsupported output format: %s", flagFormat)
	}

	return factory.
		Build().
		Output(results)
}
