package rego

import (
	"context"
	"embed"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/internal/rules"
	rules2 "github.com/aquasecurity/defsec/rules"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
)

func init() {

	modules, err := loadEmbeddedPolicies()
	if err != nil {
		// we should panic as the policies were not embedded properly
		panic(err)
	}
	loadedLibs, err := loadEmbeddedLibraries()
	if err != nil {
		panic(err)
	}
	for name, policy := range loadedLibs {
		modules[name] = policy
	}

	RegisterRegoRules(modules)
}

func RegisterRegoRules(modules map[string]*ast.Module) {
	ctx := context.TODO()

	compiler := ast.NewCompiler()
	schemaSet, _, _ := BuildSchemaSetFromPolicies(modules, nil, nil)
	compiler.WithSchemas(schemaSet)
	compiler.WithCapabilities(nil)
	compiler.Compile(modules)
	if compiler.Failed() {
		// we should panic as the embedded rego policies are syntactically incorrect...
		panic(compiler.Errors)
	}

	retriever := NewMetadataRetriever(compiler)
	for _, module := range modules {
		metadata, err := retriever.RetrieveMetadata(ctx, module)
		if err != nil {
			continue
		}
		if metadata.AVDID == "" {
			continue
		}
		rules.Register(
			metadata.ToRule(),
			nil,
		)
	}
}

func loadEmbeddedPolicies() (map[string]*ast.Module, error) {
	return RecurseEmbeddedModules(rules2.EmbeddedPolicyFileSystem, ".")
}

func loadEmbeddedLibraries() (map[string]*ast.Module, error) {
	return RecurseEmbeddedModules(rules2.EmbeddedLibraryFileSystem, ".")
}

func RecurseEmbeddedModules(fs embed.FS, dir string) (map[string]*ast.Module, error) {
	if strings.HasSuffix(dir, "policies/advanced/optional") {
		return nil, nil
	}
	dir = strings.TrimPrefix(dir, "./")
	modules := make(map[string]*ast.Module)
	entries, err := fs.ReadDir(filepath.ToSlash(dir))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			subs, err := RecurseEmbeddedModules(fs, strings.Join([]string{dir, entry.Name()}, "/"))
			if err != nil {
				return nil, err
			}
			for key, val := range subs {
				modules[key] = val
			}
			continue
		}
		if !strings.HasSuffix(entry.Name(), bundle.RegoExt) || strings.HasSuffix(entry.Name(), "_test"+bundle.RegoExt) {
			continue
		}
		fullPath := strings.Join([]string{dir, entry.Name()}, "/")
		data, err := fs.ReadFile(filepath.ToSlash(fullPath))
		if err != nil {
			return nil, err
		}
		mod, err := ast.ParseModuleWithOpts(fullPath, string(data), ast.ParserOptions{
			ProcessAnnotation: true,
		})
		if err != nil {
			return nil, err
		}
		modules[fullPath] = mod
	}
	return modules, nil
}
