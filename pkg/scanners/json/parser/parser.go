package parser

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/aquasecurity/defsec/internal/debug"
	"github.com/aquasecurity/defsec/pkg/detection"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	debug        debug.Logger
	skipRequired bool
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "parse:json")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

// New creates a new parser
func New(opts ...options.ParserOption) *Parser {
	p := &Parser{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string]interface{}, error) {

	files := make(map[string]interface{})
	if err := fs.WalkDir(target, filepath.ToSlash(path), func(path string, entry fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !p.Required(path) {
			return nil
		}
		df, err := p.ParseFile(ctx, target, path)
		if err != nil {
			p.debug.Log("Parse error in '%s': %s", path, err)
			return nil
		}
		files[path] = df
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// ParseFile parses Dockerfile content from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fs fs.FS, path string) (interface{}, error) {
	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var target interface{}
	if err := json.NewDecoder(f).Decode(&target); err != nil {
		return nil, err
	}
	return target, nil
}

func (p *Parser) Required(path string) bool {
	if p.skipRequired {
		return true
	}
	return detection.IsType(path, nil, detection.FileTypeJSON)
}
