package rego

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
)

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func (s *Scanner) loadPoliciesFromDirs(target fs.FS, paths []string) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for _, path := range paths {
		if err := fs.WalkDir(target, filepath.ToSlash(path), func(path string, info fs.DirEntry, err error) error {
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
				return err
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
		data, err := ioutil.ReadAll(r)
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

func (s *Scanner) LoadPolicies(loadEmbedded bool, srcFS fs.FS, paths []string, readers []io.Reader) error {

	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}

	if s.policyFS != nil {
		s.debug.Log("Overriding filesystem for policies!")
		srcFS = s.policyFS
	}
	loadedLibs, errLoad := loadEmbeddedLibraries()
	if errLoad != nil {
		return fmt.Errorf("failed to load embedded rego libraries: %w", errLoad)
	}
	for name, policy := range loadedLibs {
		s.policies[name] = policy
	}
	s.debug.Log("Loaded %d embedded libraries.", len(loadedLibs))

	if loadEmbedded {
		loaded, err := loadEmbeddedPolicies()
		if err != nil {
			return fmt.Errorf("failed to load embedded rego policies: %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d embedded policies.", len(loaded))
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
	store, err := initStore(s.dataDirs, namespaces)
	if err != nil {
		return fmt.Errorf("unable to load data: %w", err)
	}
	s.store = store

	compiler := ast.NewCompiler()
	schemaSet := ast.NewSchemaSet()
	schemaSet.Put(ast.MustParseRef("schema.input"), map[string]interface{}{})
	compiler.WithSchemas(schemaSet)
	compiler.Compile(s.policies)
	if compiler.Failed() {
		return compiler.Errors
	}
	retriever := NewMetadataRetriever(compiler)

	// REMOVE
	for filename, module := range s.policies {
		filename = path.Join("internal/rules", filename)
		fmt.Print(filename + " ... ")
		static, err := retriever.RetrieveMetadata(context.Background(), module)
		if err != nil {
			return err
		}

		resources := ""
		if static.PrimaryURL != "" {
			resources = fmt.Sprintf("\n# related_resources:\n# - %s", static.PrimaryURL)
		}
		shortCode := ""
		if static.ShortCode != "" {
			shortCode = fmt.Sprintf("\n#   short_code: %s", static.ShortCode)
		}
		input := ""
		if len(static.InputOptions.Selectors) > 0 {
			input = "\n#   input:\n#     selector:"
			for _, selector := range static.InputOptions.Selectors {
				if selector.Type == "defsec" {
					selector.Type = "cloud"
				}
				input += fmt.Sprintf("\n#     - type: %s", selector.Type)
			}
		}

		metadata := fmt.Sprintf(`# METADATA
# title: %s
# description: %s
# scope: package%s
# schemas:
# - input: schema["input"]
# custom:
#   id: %s
#   avd_id: %s
#   severity: %s%s
#   recommended_action: %s%s
`,
			static.Title,
			static.Description,
			resources,
			static.ID,
			static.AVDID,
			static.Severity,
			shortCode,
			static.RecommendedActions,
			input,
		)
		fmt.Println(metadata)

		before, err := os.ReadFile(filename)
		if err != nil {
			return err
		}

		if strings.Contains(string(before), "# METADATA") {
			fmt.Println("SKIPPED")
			continue
		}

		if err := os.WriteFile(filename, []byte(metadata+string(before)), 0644); err != nil {
			return err
		}
		fmt.Println("UPDATED")
	}
	// REMOVE

	if err := s.filterModules(retriever); err != nil {
		return err
	}
	if s.inputSchema != nil {
		schemaSet := ast.NewSchemaSet()
		schemaSet.Put(ast.MustParseRef("schema.input"), s.inputSchema)
		compiler.WithSchemas(schemaSet)
		compiler.Compile(s.policies)
		if compiler.Failed() {
			return compiler.Errors
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
