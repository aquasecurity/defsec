package parser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Parser struct {
	skipRequired bool
}

// New creates a new K8s parser
func New(options ...Option) *Parser {
	p := &Parser{}
	for _, option := range options {
		option(p)
	}
	return p
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
		if !p.required(ctx, target, path) {
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

// ParseFile parses Kubernetes manifest from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fs fs.FS, path string) ([]interface{}, error) {
	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return p.parse(f)
}

func (p *Parser) required(ctx context.Context, fs fs.FS, path string) bool {
	if p.skipRequired {
		return true
	}

	ext := filepath.Ext(path)
	if !strings.EqualFold(ext, ".yaml") && !strings.EqualFold(ext, ".yml") {
		return false
	}
	parsed, err := p.ParseFile(ctx, fs, path)
	if err != nil {
		// TODO: debug
		return false
	}
	if len(parsed) == 0 {
		return false
	}
	for _, partial := range parsed {
		if msi, ok := partial.(map[string]interface{}); ok {
			match := true
			for _, expected := range []string{"apiVersion", "kind", "metadata", "spec"} {
				if _, ok := msi[expected]; !ok {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

func (p *Parser) parse(r io.Reader) ([]interface{}, error) {

	contents, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var results []interface{}

	marker := "\n---\n"
	altMarker := "\r\n---\r\n"
	if bytes.Contains(contents, []byte(altMarker)) {
		marker = altMarker
	}

	for _, partial := range strings.Split(string(contents), marker) {
		var result interface{}
		if err := yaml.Unmarshal([]byte(partial), &result); err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		results = append(results, result)
	}

	return results, nil
}
