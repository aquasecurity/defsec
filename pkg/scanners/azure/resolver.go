package azure

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/types"
)

type Resolver interface {
	ResolveExpression(expression Value) Value
	SetDeployment(d *Deployment)
}

func NewResolver() Resolver {
	return &resolver{}
}

type resolver struct {
	deployment *Deployment
}

func (r *resolver) SetDeployment(d *Deployment) {
	r.deployment = d
}

func (r *resolver) ResolveExpression(expression Value) Value {
	if expression.Kind != KindExpression {
		return expression
	}
	if r.deployment == nil {
		panic("cannot resolve expression on nil deployment")
	}
	code, ok := expression.rLit.(string)
	if !ok {
		panic("cannot resolve non-string expression")
	}
	resolved, err := r.resolveExpressionString(code, expression.GetMetadata())
	if err != nil {
		expression.Kind = KindUnresolvable
		return expression
	}
	return resolved
}

func (r *resolver) resolveExpressionString(code string, metadata types.Metadata) (Value, error) {
	tokens, err := lex(code)
	if err != nil {
		return NullValue, err
	}

	// TODO: build AST + evaluate
	_ = tokens
	_ = metadata

	return NullValue, fmt.Errorf("not implemented yet")
}
