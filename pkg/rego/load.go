package rego

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
)

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func isJSONFile(name string) bool {
	return strings.HasSuffix(name, ".json")
}

func sanitisePath(path string) string {
	vol := filepath.VolumeName(path)
	path = strings.TrimPrefix(path, vol)

	return strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "./"), "/")
}

func (s *Scanner) loadPoliciesFromDirs(target fs.FS, paths []string) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for _, path := range paths {
		if err := fs.WalkDir(target, sanitisePath(path), func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !isRegoFile(info.Name()) {
				return nil
			}
			data, err := fs.ReadFile(target, filepath.ToSlash(path))
			if err != nil {
				return err
			}
			module, err := ast.ParseModuleWithOpts(path, string(data), ast.ParserOptions{
				ProcessAnnotation: true,
			})
			if err != nil {
				s.debug.Log("Failed to load module: %s, err: %s", filepath.ToSlash(path), err.Error())
				return nil
			}
			modules[path] = module
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return modules, nil
}

func (s *Scanner) loadPoliciesFromReaders(readers []io.Reader) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for i, r := range readers {
		moduleName := fmt.Sprintf("reader_%d", i)
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		module, err := ast.ParseModuleWithOpts(moduleName, string(data), ast.ParserOptions{
			ProcessAnnotation: true,
		})
		if err != nil {
			return nil, err
		}
		modules[moduleName] = module
	}
	return modules, nil
}

func (s *Scanner) LoadEmbeddedLibraries() error {
	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}
	loadedLibs, err := loadEmbeddedLibraries()
	if err != nil {
		return fmt.Errorf("failed to load embedded rego libraries: %w", err)
	}
	for name, policy := range loadedLibs {
		s.policies[name] = policy
	}
	s.debug.Log("Loaded %d embedded libraries (without embedded policies).", len(loadedLibs))
	return nil
}

func (s *Scanner) loadEmbedded(enableEmbeddedLibraries, enableEmbeddedPolicies bool) error {
	if enableEmbeddedLibraries {
		loadedLibs, errLoad := loadEmbeddedLibraries()
		if errLoad != nil {
			return fmt.Errorf("failed to load embedded rego libraries: %w", errLoad)
		}
		for name, policy := range loadedLibs {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d embedded libraries.", len(loadedLibs))
	}

	if enableEmbeddedPolicies {
		loaded, err := loadEmbeddedPolicies()
		if err != nil {
			return fmt.Errorf("failed to load embedded rego policies: %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d embedded policies.", len(loaded))
	}

	return nil
}

func (s *Scanner) LoadPolicies(enableEmbeddedLibraries, enableEmbeddedPolicies bool, srcFS fs.FS, paths []string, readers []io.Reader) error {

	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}

	if s.policyFS != nil {
		s.debug.Log("Overriding filesystem for policies!")
		srcFS = s.policyFS
	}

	if err := s.loadEmbedded(enableEmbeddedLibraries, enableEmbeddedPolicies); err != nil {
		return err
	}

	var err error
	if len(paths) > 0 {
		loaded, err := s.loadPoliciesFromDirs(srcFS, paths)
		if err != nil {
			return fmt.Errorf("failed to load rego policies from %s: %w", paths, err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d policies from disk.", len(loaded))
	}

	if len(readers) > 0 {
		loaded, err := s.loadPoliciesFromReaders(readers)
		if err != nil {
			return fmt.Errorf("failed to load rego policies from reader(s): %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d policies from reader(s).", len(loaded))
	}

	// gather namespaces
	uniq := make(map[string]struct{})
	for _, module := range s.policies {
		namespace := getModuleNamespace(module)
		uniq[namespace] = struct{}{}
	}
	var namespaces []string
	for namespace := range uniq {
		namespaces = append(namespaces, namespace)
	}

	dataFS := srcFS
	if s.dataFS != nil {
		s.debug.Log("Overriding filesystem for data!")
		dataFS = s.dataFS
	}
	store, err := initStore(dataFS, s.dataDirs, namespaces)
	if err != nil {
		return fmt.Errorf("unable to load data: %w", err)
	}
	s.store = store

	return s.compilePolicies(srcFS, paths)
}

func (s *Scanner) prunePoliciesWithError(compiler *ast.Compiler) error {
	if len(compiler.Errors) > s.regoErrorLimit {
		s.debug.Log("Error(s) occurred while loading policies")
		return compiler.Errors
	}

	for _, e := range compiler.Errors {
		s.debug.Log("Error occurred while parsing: %s, %s", e.Location.File, e.Error())
		delete(s.policies, e.Location.File)
	}
	return nil
}

func (s *Scanner) compilePolicies(srcFS fs.FS, paths []string) error {
	compiler := ast.NewCompiler()
	schemaSet, custom, err := BuildSchemaSetFromPolicies(s.policies, paths, srcFS)
	if err != nil {
		return err
	}
	if custom {
		s.inputSchema = nil // discard auto detected input schema in favour of policy defined schema
	}

	compiler.WithSchemas(schemaSet)
	compiler.WithCapabilities(ast.CapabilitiesForThisVersion())
	compiler.Compile(s.policies)
	if compiler.Failed() {
		if err := s.prunePoliciesWithError(compiler); err != nil {
			return err
		}
		return s.compilePolicies(srcFS, paths)
	}
	retriever := NewMetadataRetriever(compiler)

	if err := s.filterModules(retriever); err != nil {
		return err
	}
	if s.inputSchema != nil {
		schemaSet := ast.NewSchemaSet()
		schemaSet.Put(ast.MustParseRef("schema.input"), s.inputSchema)
		compiler.WithSchemas(schemaSet)
		compiler.Compile(s.policies)
		if compiler.Failed() {
			if err := s.prunePoliciesWithError(compiler); err != nil {
				return err
			}
			return s.compilePolicies(srcFS, paths)
		}
	}
	s.compiler = compiler
	s.retriever = retriever
	return nil
}

func (s *Scanner) filterModules(retriever *MetadataRetriever) error {

	filtered := make(map[string]*ast.Module)
	for name, module := range s.policies {
		meta, err := retriever.RetrieveMetadata(context.TODO(), module)
		if err != nil {
			return err
		}
		if len(meta.InputOptions.Selectors) == 0 {
			s.debug.Log("WARNING: Module %s has no input selectors - it will be loaded for all inputs!", name)
			filtered[name] = module
			continue
		}
		for _, selector := range meta.InputOptions.Selectors {
			if selector.Type == string(s.sourceType) {
				filtered[name] = module
				break
			}
		}
	}

	s.policies = filtered
	return nil
}
