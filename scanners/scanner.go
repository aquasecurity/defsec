package scanners

import (
	"context"
	"io/fs"
	"os"

	"github.com/aquasecurity/defsec/rules"
)

type WriteFileFS interface {
	WriteFile(name string, data []byte, perm os.FileMode) error
}

type Scanner interface {
	ScanFS(ctx context.Context, fs fs.FS, dir string) (rules.Results, error)
	ScanFile(ctx context.Context, fs fs.FS, path string) (rules.Results, error)
}
