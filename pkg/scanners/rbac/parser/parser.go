package parser

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"io/ioutil"
	"path/filepath"

	"github.com/aquasecurity/defsec/pkg/debug"

	"github.com/aquasecurity/defsec/pkg/detection"
	k8s "github.com/aquasecurity/defsec/pkg/scanners/kubernetes/parser"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

var _ options.ConfigurableParser = (*Parser)(nil)

type Parser struct {
	k8s.Parser
	debug        debug.Logger
	skipRequired bool
}

func (p *Parser) SetDebugWriter(writer io.Writer) {
	p.debug = debug.New(writer, "rbac", "parser")
}

func (p *Parser) SetSkipRequiredCheck(b bool) {
	p.skipRequired = b
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string][]interface{}, error) {
	files := make(map[string][]interface{})
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
		if !p.required(target, path) {
			return nil
		}
		parsed, err := p.ParseFile(ctx, target, path)
		if err != nil {
			p.debug.Log("Parse error in '%s': %s", path, err)
			return nil
		}
		files[path] = parsed
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// New creates a new K8s parser
func New(options ...options.ParserOption) *Parser {
	p := &Parser{}
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *Parser) required(fs fs.FS, path string) bool {
	if p.skipRequired {
		return true
	}
	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if data, err := ioutil.ReadAll(f); err == nil {
		return detection.IsType(path, bytes.NewReader(data), detection.FileTypeRbac)
	}
	return false
}
