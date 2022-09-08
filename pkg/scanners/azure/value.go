package azure

import (
	"github.com/aquasecurity/defsec/pkg/scanners/azure/arm/parser/armjson"
	"github.com/aquasecurity/defsec/pkg/types"
)

type Resolver interface {
	Resolve(name string) Value
}

type EvalContext struct{}

type Kind string

const (
	KindUnresolvable Kind = "unresolvable"
	KindBoolean      Kind = "boolean"
	KindString       Kind = "string"
	KindNumber       Kind = "number"
	KindObject       Kind = "object"
	KindNull         Kind = "null"
	KindArray        Kind = "array"
	KindFunction     Kind = "function"
)

type Value struct {
	*types.Metadata
	rLit     interface{}
	rMap     map[string]Value
	rArr     []Value
	Kind     Kind
	Comments []string
}

func NewValue(value interface{}, metadata types.Metadata) Value {

	v := Value{
		Metadata: &metadata,
	}

	switch ty := value.(type) {
	case []interface{}:
		v.Kind = KindArray
		for _, child := range ty {
			if internal, ok := child.(Value); ok {
				v.rArr = append(v.rArr, internal)
			} else {
				v.rArr = append(v.rArr, NewValue(child, metadata))
			}
		}
	case []Value:
		v.Kind = KindArray
		for _, child := range ty {
			v.rArr = append(v.rArr, child)
		}
	case map[string]interface{}:
		v.Kind = KindObject
		v.rMap = make(map[string]Value)
		for key, val := range ty {
			if internal, ok := val.(Value); ok {
				v.rMap[key] = internal
			} else {
				v.rMap[key] = NewValue(val, metadata)
			}
		}
	case map[string]Value:
		v.Kind = KindObject
		v.rMap = make(map[string]Value)
		for key, val := range ty {
			v.rMap[key] = val
		}
	case string:
		v.Kind = KindString
		v.rLit = ty
	case int, int64, int32, float32, float64, int8, int16, uint8, uint16, uint32, uint64:
		v.Kind = KindNumber
		v.rLit = ty
	case bool:
		v.Kind = KindBoolean
		v.rLit = ty
	case nil:
		v.Kind = KindNull
		v.rLit = ty
	default:
		v.Kind = KindUnresolvable
		v.rLit = ty
	}

	return v
}

func (v *Value) UnmarshalJSONWithMetadata(node armjson.Node) error {

	switch node.Kind() {
	case armjson.KindString:
		v.Kind = KindString
	case armjson.KindNumber:
		v.Kind = KindNumber
	case armjson.KindBoolean:
		v.Kind = KindBoolean
	case armjson.KindObject:
		v.Kind = KindObject
	case armjson.KindNull:
		v.Kind = KindNull
	case armjson.KindArray:
		v.Kind = KindArray
	default:
		panic(node.Kind())
	}

	v.Metadata = node.Metadata()

	switch node.Kind() {
	case armjson.KindArray:
		var arr []Value
		for _, child := range node.Content() {
			var val Value
			if err := val.UnmarshalJSONWithMetadata(child); err != nil {
				return err
			}
			arr = append(arr, val)
		}
		v.rArr = arr
	case armjson.KindObject:
		obj := make(map[string]Value)
		for i := 0; i < len(node.Content()); i += 2 {
			var key string
			if err := node.Content()[i].Decode(&key); err != nil {
				return err
			}
			var val Value
			if err := val.UnmarshalJSONWithMetadata(node.Content()[i+1]); err != nil {
				return err
			}
			obj[key] = val
		}
		v.rMap = obj
	default:
		if err := node.Decode(&v.rLit); err != nil {
			return err
		}
	}

	for _, comment := range node.Comments() {
		var str string
		if err := comment.Decode(&str); err != nil {
			return err
		}
		v.Comments = append(v.Comments, str)
	}
	return nil
}

func (v *Value) AsString() string {
	if v.Kind != KindString {
		return ""
	}
	return v.rLit.(string)
}

func (v *Value) AsMap() map[string]Value {
	if v.Kind != KindObject {
		return nil
	}
	return v.rMap
}

func (v *Value) AsList() []Value {
	if v.Kind != KindArray {
		return nil
	}
	return v.rArr
}

func (v *Value) Raw() interface{} {
	switch v.Kind {
	case KindArray:
		// TODO: recursively build raw array
		return nil
	case KindObject:
		// TODO: recursively build raw object
		return nil
	default:
		return v.rLit
	}
}
