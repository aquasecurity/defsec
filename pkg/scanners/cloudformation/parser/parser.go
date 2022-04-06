package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/liamg/jfather"
	"gopkg.in/yaml.v3"
)

type Parser struct {
	parameters  map[string]Parameter
	debugWriter io.Writer
}

func New(options ...Option) *Parser {
	p := &Parser{}
	for _, option := range options {
		option(p)
	}
	return p
}

func (p *Parser) debug(format string, args ...interface{}) {
	if p.debugWriter == nil {
		return
	}
	prefix := "[debug:parse] "
	_, _ = p.debugWriter.Write([]byte(fmt.Sprintf(prefix+format+"\n", args...)))
}

func (p *Parser) ParseFS(ctx context.Context, target fs.FS, dir string) (FileContexts, error) {
	var contexts FileContexts
	if err := fs.WalkDir(target, filepath.ToSlash(dir), func(path string, entry fs.DirEntry, err error) error {
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
			p.debug("not a CloudFormation file, skipping %s", path)
			return nil
		}

		c, err := p.ParseFile(ctx, target, path)
		if err != nil {
			return err
		}
		contexts = append(contexts, c)
		return nil
	}); err != nil {
		return nil, err
	}
	return contexts, nil
}

func (p *Parser) Required(fs fs.FS, path string) bool {

	var unmarshalFunc func([]byte, interface{}) error

	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		unmarshalFunc = yaml.Unmarshal
	case ".json":
		unmarshalFunc = json.Unmarshal
	default:
		return false
	}

	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return false
	}

	contents := make(map[string]interface{})
	if err := unmarshalFunc(data, &contents); err != nil {
		p.debug("file '%s' is not valid: %s", path, err)
		return false
	}
	_, ok := contents["Resources"]
	return ok
}

func (p *Parser) ParseFile(ctx context.Context, fs fs.FS, path string) (context *FileContext, err error) {

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic during parse: %s", e)
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	sourceFmt := YamlSourceFormat
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		sourceFmt = JsonSourceFormat
	}

	f, err := fs.Open(filepath.ToSlash(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	content, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	context = &FileContext{
		filepath:     path,
		lines:        lines,
		SourceFormat: sourceFmt,
	}

	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := jfather.Unmarshal(content, context); err != nil {
			return nil, NewErrInvalidContent(path, err)
		}
	} else {
		if err := yaml.Unmarshal(content, context); err != nil {
			return nil, NewErrInvalidContent(path, err)
		}
	}

	context.lines = lines
	context.SourceFormat = sourceFmt
	context.filepath = path

	p.debug("Context loaded from source %s", path)

	for name, r := range context.Resources {
		r.ConfigureResource(name, path, context)
	}

	if p.parameters != nil {
		for name, passedParameter := range p.parameters {
			context.Parameters[name].UpdateDefault(passedParameter.Default())
		}
	}

	return context, nil
}
