package parser

import (
	"strconv"
	"strings"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/cftypes"
)

func (p *Property) IsNil() bool {
	return p == nil || p.Inner.Value == nil
}

func (p *Property) IsNotNil() bool {
	return !p.IsUnresolved() && !p.IsNil()
}

func (p *Property) IsString() bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.IsString()
		}
	}
	return p.Inner.Type == cftypes.String
}

func (p *Property) IsNotString() bool {
	return !p.IsUnresolved() && !p.IsString()
}

func (p *Property) IsInt() bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.IsInt()
		}
	}
	return p.Inner.Type == cftypes.Int
}

func (p *Property) IsNotInt() bool {
	return !p.IsUnresolved() && !p.IsInt()
}

func (p *Property) IsMap() bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	return p.Inner.Type == cftypes.Map
}

func (p *Property) IsNotMap() bool {
	return !p.IsUnresolved() && !p.IsMap()
}

func (p *Property) IsList() bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.IsList()
		}
	}
	return p.Inner.Type == cftypes.List
}

func (p *Property) IsNotList() bool {
	return !p.IsUnresolved() && !p.IsList()
}

func (p *Property) IsBool() bool {
	if p.IsNil() || p.IsUnresolved() {
		return false
	}
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.IsBool()
		}
	}
	return p.Inner.Type == cftypes.Bool
}

func (p *Property) IsUnresolved() bool {
	return p != nil && p.unresolved
}

func (p *Property) IsNotBool() bool {
	return !p.IsUnresolved() && !p.IsBool()
}

func (p *Property) AsString() string {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsString()
		}
		return ""
	}
	if p.IsNil() {
		return ""
	}
	if !p.IsString() {
		return ""
	}

	return p.Inner.Value.(string)
}

func (p *Property) AsStringValue() defsecTypes.StringValue {
	if p.unresolved {
		return defsecTypes.StringUnresolvable(p.Metadata())
	}
	return defsecTypes.StringExplicit(p.AsString(), p.Metadata())
}

func (p *Property) AsInt() int {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsInt()
		}
		return 0
	}
	if p.IsNotInt() {
		if p.isConvertableToInt() {
			return p.convertToInt().AsInt()
		}
		return 0
	}

	return p.Inner.Value.(int)
}

func (p *Property) AsIntValue() defsecTypes.IntValue {
	if p.unresolved {
		return defsecTypes.IntUnresolvable(p.Metadata())
	}
	return defsecTypes.IntExplicit(p.AsInt(), p.Metadata())
}

func (p *Property) AsBool() bool {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsBool()
		}
		return false
	}
	if !p.IsBool() {
		return false
	}
	return p.Inner.Value.(bool)
}

func (p *Property) AsBoolValue() defsecTypes.BoolValue {
	if p.unresolved {
		return defsecTypes.BoolUnresolvable(p.Metadata())
	}
	return defsecTypes.Bool(p.AsBool(), p.Metadata())
}

func (p *Property) AsMap() map[string]*Property {
	val, ok := p.Inner.Value.(map[string]*Property)
	if !ok {
		return nil
	}
	return val
}

func (p *Property) AsList() []*Property {
	if p.isFunction() {
		if prop, success := p.resolveValue(); success && prop != p {
			return prop.AsList()
		}
		return []*Property{}
	}

	if list, ok := p.Inner.Value.([]*Property); ok {
		return list
	}
	return nil
}

func (p *Property) EqualTo(checkValue interface{}, equalityOptions ...EqualityOptions) bool {
	var ignoreCase bool
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}

	switch checkerVal := checkValue.(type) {
	case string:
		if p.IsNil() {
			return false
		}

		switch p.Inner.Type {
		case cftypes.String:
			if ignoreCase {
				return strings.EqualFold(p.AsString(), checkerVal)
			}
			return p.AsString() == checkerVal
		case cftypes.Int:
			if val, err := strconv.Atoi(checkerVal); err == nil {
				return p.AsInt() == val
			}
		}
		return false
	case bool:
		return p.Inner.Value == checkerVal
	case int:
		return p.Inner.Value == checkerVal
	}

	return false

}

func (p *Property) IsTrue() bool {
	if p.IsNil() || !p.IsBool() {
		return false
	}

	return p.AsBool()
}

func (p *Property) IsEmpty() bool {

	if p.IsNil() {
		return true
	}
	if p.IsUnresolved() {
		return false
	}

	switch p.Inner.Type {
	case cftypes.String:
		return p.AsString() == ""
	case cftypes.List, cftypes.Map:
		return len(p.AsList()) == 0
	default:
		return false
	}
}

func (p *Property) Contains(checkVal interface{}) bool {
	if p == nil || p.IsNil() {
		return false
	}

	switch p.Type() {
	case cftypes.List:
		for _, p := range p.AsList() {
			if p.EqualTo(checkVal) {
				return true
			}
		}
	case cftypes.Map:
		if _, ok := checkVal.(string); !ok {
			return false
		}
		for key := range p.AsMap() {
			if key == checkVal.(string) {
				return true
			}
		}
	case cftypes.String:
		if _, ok := checkVal.(string); !ok {
			return false
		}
		return strings.Contains(p.AsString(), checkVal.(string))
	}
	return false
}
