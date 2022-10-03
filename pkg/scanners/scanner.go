package scanners

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
)

type WriteFileFS interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type FSScanner interface {
	// Name provides the human-readable name of the scanner e.g. "CloudFormation"
	Name() string
	// ScanFS scans the given filesystem for issues, starting at the provided directory.
	// Use '.' to scan an entire filesystem.
	ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error)
}

type APIScanner interface {
	// Name provides the human-readable name of the scanner e.g. "AWS API"
	Name() string

	// Scan scans an API and returns results
	Scan(ctx context.Context, cloud *state.State) (scan.Results, error)
}
