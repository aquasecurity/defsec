package adapter

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	defaultProviderPackage = "github.com/aquasecurity/defsec/pkg/providers"
	defaultTypesPackage    = "github.com/aquasecurity/defsec/pkg/types"
)

func DefaultAnalyzer() *analysis.Analyzer {
	return CreateAnalyzer(defaultProviderPackage, defaultTypesPackage)
}

func CreateAnalyzer(providerPackage, typesPackage string) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "adapter",
		Doc:      "reports provider struct initialisations with omitted 'types' fields",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run: func(pass *analysis.Pass) (interface{}, error) {

			if err := detectNamedFunctionReturns(pass, providerPackage); err != nil {
				return nil, err
			}

			if err := detectEmptyStructInit(pass, providerPackage); err != nil {
				return nil, err
			}

			if err := detectMissingTypesFields(pass, providerPackage, typesPackage); err != nil {
				return nil, err
			}

			if err := detectMetadataLiterals(pass, typesPackage); err != nil {
				return nil, err
			}

			return nil, nil
		},
	}
}

func detectMetadataLiterals(pass *analysis.Pass, typesPackage string) error {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{
		(*ast.CompositeLit)(nil),
	}, func(n ast.Node) {

		if strings.HasSuffix(pass.Fset.File(n.Pos()).Name(), "_test.go") {
			return
		}

		lit := n.(*ast.CompositeLit)
		if lit.Type == nil {
			return
		}

		tx := pass.TypesInfo.TypeOf(lit.Type)
		if tx == nil {
			return
		}

		if !strings.HasPrefix(tx.String(), typesPackage) {
			return
		}

		named, ok := tx.(*types.Named)
		if !ok {
			return
		}

		if named.String() == fmt.Sprintf("%s.Metadata", typesPackage) {
			pass.Reportf(lit.Pos(), "Metadata instances should not be initialised using literals")
		}
	})
	return nil

}

func detectNamedFunctionReturns(pass *analysis.Pass, providerPackage string) error {
	for _, f := range pass.Files {
		for _, d := range f.Decls {
			switch fnc := d.(type) {
			case *ast.FuncDecl:
				if fnc.Type.Results == nil {
					continue
				}
				for _, result := range fnc.Type.Results.List {
					for _, name := range result.Names {
						if field, ok := name.Obj.Decl.(*ast.Field); ok {
							tx := pass.TypesInfo.TypeOf(field.Type)
							if tx == nil {
								continue
							}

							if !strings.HasPrefix(tx.String(), providerPackage) {
								continue
							}

							if strings.HasSuffix(pass.Fset.File(field.Pos()).Name(), "_test.go") {
								continue
							}

							pass.Reportf(field.Pos(), "Provider struct %s should not be initialised via a named function return type", tx.String())
						}
					}
				}
			}
		}
	}
	return nil
}

func detectEmptyStructInit(pass *analysis.Pass, providerPackage string) error {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{
		(*ast.DeclStmt)(nil),
	}, func(n ast.Node) {

		if strings.HasSuffix(pass.Fset.File(n.Pos()).Name(), "_test.go") {
			return
		}

		decl := n.(*ast.DeclStmt)
		gen, ok := decl.Decl.(*ast.GenDecl)
		if !ok {
			return
		}
		for _, spec := range gen.Specs {
			u, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}

			tx := pass.TypesInfo.TypeOf(u.Type)
			if tx == nil {
				return
			}

			if !strings.HasPrefix(tx.String(), providerPackage) {
				continue
			}
			pass.Reportf(n.Pos(), "Provider struct %s should be explicitly initialised with all fields provided", tx.String())
		}
	})
	return nil
}
func detectMissingTypesFields(pass *analysis.Pass, providerPackage, typesPackage string) error {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	insp.Preorder([]ast.Node{
		(*ast.CompositeLit)(nil),
	}, func(n ast.Node) {

		if strings.HasSuffix(pass.Fset.File(n.Pos()).Name(), "_test.go") {
			return
		}

		lit := n.(*ast.CompositeLit)
		if lit.Type == nil {
			return
		}

		tx := pass.TypesInfo.TypeOf(lit.Type)
		if tx == nil {
			return
		}

		if !strings.HasPrefix(tx.String(), providerPackage) {
			return
		}

		named, ok := tx.(*types.Named)
		if !ok {
			return
		}

		switch u := named.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				field := u.Field(i)
				if !strings.HasPrefix(field.Type().String(), typesPackage) {
					continue
				}
				var found bool
				for j, included := range lit.Elts {
					switch et := included.(type) {
					case *ast.KeyValueExpr:
						if et.Key.(*ast.Ident).Name == field.Name() {
							found = true
						}
					default:
						found = found || i == j
					}
					if found {
						break
					}
				}
				if !found {
					pass.Reportf(lit.Pos(), "Provider struct %s is missing an initialised value for field '%s'", named.String(), field.Name())
				}
			}
		}
	})
	return nil
}
