package parser

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser/resolvers"
	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/zclconf/go-cty/cty"
)

type moduleLoadError struct {
	source string
	err    error
}

func (m *moduleLoadError) Error() string {
	return fmt.Sprintf("failed to load module '%s': %s", m.source, m.err)
}

type ModuleDefinition struct {
	Name       string
	Path       string
	Definition *terraform.Block
	Parser     *Parser
}

// LoadModules reads all module blocks and loads the underlying modules, adding blocks to e.moduleBlocks
func (e *evaluator) loadModules(ctx context.Context, fs fs.FS) []*ModuleDefinition {

	blocks := e.blocks

	var moduleDefinitions []*ModuleDefinition

	expanded := e.expandBlocks(blocks.OfType("module"))

	var loadErrors []*moduleLoadError

	for _, moduleBlock := range expanded {
		if moduleBlock.Label() == "" {
			continue
		}
		moduleDefinition, err := e.loadModule(ctx, moduleBlock, fs)
		if err != nil {
			var loadErr *moduleLoadError
			if errors.As(err, &loadErr) {
				var found bool
				for _, fm := range loadErrors {
					if fm.source == loadErr.source {
						found = true
						break
					}
				}
				if !found {
					loadErrors = append(loadErrors, loadErr)
				}
				continue
			}
			e.debug("Failed to load module '%s'. Maybe try 'terraform init'?", err)
			continue
		}
		e.debug("Loaded module '%s' from '%s'.", moduleDefinition.Name, moduleDefinition.Path)
		moduleDefinitions = append(moduleDefinitions, moduleDefinition)
	}

	return moduleDefinitions
}

// takes in a module "x" {} block and loads resources etc. into e.moduleBlocks - additionally returns variables to add to ["module.x.*"] variables
func (e *evaluator) loadModule(ctx context.Context, b *terraform.Block, target fs.FS) (*ModuleDefinition, error) {

	metadata := b.GetMetadata()

	if b.Label() == "" {
		return nil, fmt.Errorf("module without label at %s", metadata.Range())
	}

	var source string
	attrs := b.Attributes()
	for _, attr := range attrs {
		if attr.Name() == "source" {
			sourceVal := attr.Value()
			if sourceVal.Type() == cty.String {
				source = sourceVal.AsString()
			}
		}
	}

	if source == "" {
		return nil, fmt.Errorf("could not read module source attribute at %s", metadata.Range().String())
	}

	var modulePath string

	if e.moduleMetadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!
		name := b.ModuleName()
		for _, module := range e.moduleMetadata.Modules {
			if module.Key == name {
				modulePath = filepath.Clean(filepath.Join(e.projectRootPath, module.Dir))
				break
			}
		}
	}
	if modulePath == "" {

		version := b.GetAttribute("version").AsStringValueOrDefault("", b).Value()
		opt := resolvers.Options{
			Source:         source,
			Version:        version,
			WorkingDir:     e.projectRootPath,
			Name:           b.FullName(),
			ModulePath:     e.modulePath,
			DebugWriter:    e.debugWriter,
			AllowDownloads: e.allowDownloads,
		}
		path, err := resolveModule(ctx, opt)
		if err != nil {
			return nil, err
		}
		e.debug("Module '%s' resolved to path '%s'", b.FullName(), path)
		modulePath = path
	}

	moduleParser := e.parentParser.newModuleParser(modulePath, b.Label(), b)
	if err := moduleParser.ParseFS(ctx, target, modulePath); err != nil {
		return nil, err
	}

	return &ModuleDefinition{
		Name:       b.Label(),
		Path:       modulePath,
		Definition: b,
		Parser:     moduleParser,
	}, nil
}
