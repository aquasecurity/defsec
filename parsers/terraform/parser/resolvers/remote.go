package resolvers

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-getter"
	"golang.org/x/xerrors"
)

type remoteResolver struct{}

var Remote = &remoteResolver{}

func (r *remoteResolver) Resolve(ctx context.Context, opt Options) (downloadPath string, applies bool, err error) {
	if !opt.hasPrefix("github.com/", "bitbucket.org/", "s3:", "git@", "git:", "hg:", "https:", "gcs:") {
		return "", false, nil
	}

	if !opt.AllowDownloads {
		return "", false, nil
	}

	cacheDir := getCacheDir(opt.WorkingDir, opt.Name)
	if err := r.download(ctx, opt, cacheDir); err != nil {
		return "", true, err
	}
	if err := writeCacheRecord(cacheDir, opt.Source, opt.Version); err != nil {
		return "", true, err
	}
	return cacheDir, true, nil
}

func (r *remoteResolver) download(ctx context.Context, opt Options, dst string) error {
	_ = os.RemoveAll(dst)
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}

	var opts []getter.ClientOption

	// Overwrite the file getter so that a file will be copied
	getter.Getters["file"] = &getter.FileGetter{Copy: true}

	// Build the client
	client := &getter.Client{
		Ctx:     ctx,
		Src:     opt.Source,
		Dst:     dst,
		Pwd:     opt.WorkingDir,
		Getters: getter.Getters,
		Mode:    getter.ClientModeAny,
		Options: opts,
	}

	if err := client.Get(); err != nil {
		return xerrors.Errorf("failed to download: %w", err)
	}

	opt.Debug("Module '%s' resolving via remote download...", opt.Name)
	return nil
}
