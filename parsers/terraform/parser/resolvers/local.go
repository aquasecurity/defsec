package resolvers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type localResolver struct{}

var Local = &localResolver{}

func (r *localResolver) Resolve(_ context.Context, opt Options) (downloadPath string, applies bool, err error) {
	if !opt.hasPrefix(fmt.Sprintf(".%c", os.PathSeparator), fmt.Sprintf("..%c", os.PathSeparator)) {
		return "", false, nil
	}
	source := filepath.Clean(filepath.Join(opt.ModulePath, opt.Source))
	opt.Debug("Module '%s' resolving via local (in %s)...", opt.Name, opt.ModulePath)
	return source, true, nil
}
