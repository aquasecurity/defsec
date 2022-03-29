package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Parser struct{}

// New creates a new K8s parser
func New() *Parser {
	return &Parser{}
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, path string) (map[string]interface{}, error) {

	files := make(map[string]interface{})
	if err := fs.WalkDir(target, path, func(path string, entry fs.DirEntry, err error) error {
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
		if !p.Required(target, path) {
			return nil
		}
		parsed, err := p.ParseFile(ctx, target, path)
		if err != nil {
			// TODO add debug for parse errors
			return nil
		}
		files[path] = parsed
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// ParseFile parses Dockerfile content from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fs fs.FS, path string) (interface{}, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return p.parse(f)
}

func (p *Parser) Required(fs fs.FS, path string) bool {
	ext := filepath.Ext(path)
	if !strings.EqualFold(ext, ".yaml") && !strings.EqualFold(ext, ".yml") {
		return false
	}
	parsed, err := p.ParseFile(context.TODO(), fs, path)
	if err != nil {
		// TODO: debug
		return false
	}
	if msi, ok := parsed.(map[string]interface{}); ok {
		match := true
		for _, expected := range []string{"apiVersion", "kind", "metadata", "spec"} {
			if _, ok := msi[expected]; !ok {
				match = false
				break
			}
		}
		return match
	}
	return false
}

func (p *Parser) parse(r io.Reader) (interface{}, error) {
	var v interface{}
	if err := yaml.NewDecoder(r).Decode(&v); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	return v, nil
}
