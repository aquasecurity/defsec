package parser

import (
	"bytes"
	"context"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Parser struct{}

// New creates a new parser
func New() *Parser {
	return &Parser{}
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
		if !p.Required(path) {
			return nil
		}
		df, err := p.ParseFile(ctx, target, path)
		if err != nil {
			// TODO add debug for parse errors
			return nil
		}
		files[path] = df
		return nil
	}); err != nil {
		return nil, err
	}
	return files, nil
}

// ParseFile parses yaml content from the provided filesystem path.
func (p *Parser) ParseFile(_ context.Context, fs fs.FS, path string) ([]interface{}, error) {
	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	contents, err := ioutil.ReadAll(f)
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
		var target interface{}
		if err := yaml.Unmarshal([]byte(partial), &target); err != nil {
			return nil, err
		}
		results = append(results, target)
	}

	return results, nil
}

func (p *Parser) Required(path string) bool {
	ext := filepath.Ext(filepath.Base(path))
	return strings.EqualFold(ext, ".yaml") || strings.EqualFold(ext, ".yml")
}
