package azure

import (
	"fmt"

	"github.com/aquasecurity/defsec/pkg/types"
)

type Value interface {
	Type() Type
	Value() (interface{}, error)
}

type val struct {
	t        Type
	value    interface{}
	resolver Resolver
	metadata types.Metadata
}

func NewValue(raw interface{}, metadata types.Metadata, resolver Resolver) Value {
	// TODO: figure out type
	return &val{
		t:        TypeUnknown,
		value:    raw,
		metadata: metadata,
		resolver: resolver,
	}
}

type Resolver interface {
	Resolve(name string) Value
}

func (v *val) Type() Type {
	return v.t
}

type EvalContext struct{}

func (v *val) Value() (interface{}, error) {
	switch v.t {
	case TypeFunction:
		// eval function here using resolver etc.
		return nil, fmt.Errorf("not implemented yet")
	case TypeUnknown:
		return nil, fmt.Errorf("unknown type")
	case TypeUnresolvable:
		return nil, fmt.Errorf("unresolvable type")
	default:
		return v.value, nil
	}
}

type Type uint8

const (
	TypeUnknown Type = iota
	TypeUnresolvable
	TypeString
	TypeInt
	TypeFloat
	TypeBool
	TypeArray
	TypeObject
	TypeFunction
)
