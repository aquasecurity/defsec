package scanners

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/defsec/pkg/scan"
)

type WriteFileFS interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type Scanner interface {
	ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error)
}
