package resolvers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type localResolver struct{}

var Local = &localResolver{}

func (r *localResolver) Resolve(_ context.Context, target fs.FS, opt Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error) {
	if !opt.hasPrefix(".", "..") {
		return nil, "", "", false, nil
	}

	srcFullPath := filepath.Clean(filepath.Join(opt.ModulePath, opt.Source))

	if same, err := sameModule(
		target,
		filepath.ToSlash(filepath.Clean(opt.ModulePath)),
		filepath.ToSlash(srcFullPath),
	); err != nil {
		return nil, "", "", false, err
	} else if same {
		return nil, "", "", false, fmt.Errorf("module %q cannot use itself as a child", opt.Name)
	}

	opt.Debug("Module '%s' resolved locally to %s", opt.Name, srcFullPath)
	return target, "", srcFullPath, true, nil
}

func sameModule(fsys fs.FS, module, childModule string) (bool, error) {
	fi1, err := fs.Stat(fsys, module)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("file stat error: %w", err)
	}

	fi2, err := fs.Stat(fsys, childModule)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("module %q not found", childModule)
		}
		return false, fmt.Errorf("file stat error: %w", err)
	}

	return os.SameFile(fi1, fi2), nil
}
