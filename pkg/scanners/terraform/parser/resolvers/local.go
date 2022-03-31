package resolvers

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type localResolver struct{}

var Local = &localResolver{}

func (r *localResolver) Resolve(_ context.Context, target fs.FS, opt Options) (filesystem fs.FS, prefix string, downloadPath string, applies bool, err error) {
	if !opt.hasPrefix(fmt.Sprintf(".%c", os.PathSeparator), fmt.Sprintf("..%c", os.PathSeparator)) {
		return nil, "", "", false, nil
	}

	opt.Debug("Module '%s' resolved locally: %#v", opt.Name, opt)
	joined := filepath.Clean(filepath.Join(opt.ModulePath, opt.Source))
	opt.Debug("Trying joined: %s (from %s -> %s)", joined, opt.ModulePath, opt.Source)
	if _, err := fs.Stat(target, joined); err == nil {
		return target, "", joined, true, nil
	}

	opt.Debug("Nope, trying literal: %s", opt.Source)
	return target, "", filepath.Clean(opt.Source), true, nil
}
