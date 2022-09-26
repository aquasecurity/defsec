package rego

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

func updateMetadata(metadata map[string]*ast.Term, input *ast.Term) map[string]*ast.Term {
	if term := input.Get(ast.StringTerm("startline")); term != nil {
		metadata["startline"] = term
	}
	if term := input.Get(ast.StringTerm("StartLine")); term != nil {
		metadata["startline"] = term
	}
	if term := input.Get(ast.StringTerm("endline")); term != nil {
		metadata["endline"] = term
	}
	if term := input.Get(ast.StringTerm("EndLine")); term != nil {
		metadata["endline"] = term
	}
	if term := input.Get(ast.StringTerm("filepath")); term != nil {
		metadata["filepath"] = term
	}
	if term := input.Get(ast.StringTerm("Path")); term != nil {
		metadata["filepath"] = term
	}
	if term := input.Get(ast.StringTerm("explicit")); term != nil {
		metadata["explicit"] = term
	}
	if term := input.Get(ast.StringTerm("managed")); term != nil {
		metadata["managed"] = term
	}
	if term := input.Get(ast.StringTerm("fskey")); term != nil {
		metadata["fskey"] = term
	}
	if term := input.Get(ast.StringTerm("resource")); term != nil {
		metadata["resource"] = term
	}
	return metadata
}

func init() {
	rego.RegisterBuiltin2(&rego.Function{
		Name: "result.new",
		Decl: types.NewFunction(types.Args(types.S, types.A), types.A),
	},
		func(_ rego.BuiltinContext, msg, cause *ast.Term) (*ast.Term, error) {

			metadata := map[string]*ast.Term{
				"msg":       msg,
				"startline": ast.IntNumberTerm(0),
				"endline":   ast.IntNumberTerm(0),
				"filepath":  ast.StringTerm(""),
				"explicit":  ast.BooleanTerm(false),
				"managed":   ast.BooleanTerm(true),
				"fskey":     ast.StringTerm(""),
				"resource":  ast.StringTerm(""),
			}

			// universal
			if defsec := cause.Get(ast.StringTerm("__defsec_metadata")); defsec != nil {
				metadata = updateMetadata(metadata, defsec)
			} else { // docker...
				metadata = updateMetadata(metadata, cause)
			}

			var values [][2]*ast.Term
			for key, val := range metadata {
				values = append(values, [2]*ast.Term{
					ast.StringTerm(key),
					val,
				})
			}
			return ast.ObjectTerm(values...), nil
		},
	)
}
