package types

import (
	"encoding/json"
)

type MapValue struct {
	BaseAttribute
	value map[string]string
}

func (b MapValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"value":    b.value,
		"metadata": b.metadata,
	})
}

func (b *MapValue) UnmarshalJSON(data []byte) error {
	var keys map[string]interface{}
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	if keys["value"] != nil {
		var target map[string]string
		raw, err := json.Marshal(keys["value"])
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &target); err != nil {
			return err
		}
		b.value = target
	}
	if keys["metadata"] != nil {
		raw, err := json.Marshal(keys["metadata"])
		if err != nil {
			return err
		}
		var m Metadata
		if err := json.Unmarshal(raw, &m); err != nil {
			return err
		}
		b.metadata = m
	}
	return nil
}

func Map(value map[string]string, m Metadata) MapValue {
	return MapValue{
		value:         value,
		BaseAttribute: BaseAttribute{metadata: m},
	}
}

func MapDefault(value map[string]string, m Metadata) MapValue {
	b := Map(value, m)
	b.BaseAttribute.metadata.isDefault = true
	return b
}

func MapExplicit(value map[string]string, m Metadata) MapValue {
	b := Map(value, m)
	b.BaseAttribute.metadata.isExplicit = true
	return b
}

func (b MapValue) Value() map[string]string {
	return b.value
}

func (b MapValue) GetRawValue() interface{} {
	return b.value
}

func (b MapValue) Len() int {
	return len(b.value)
}

func (b MapValue) HasKey(key string) bool {
	if b.value == nil {
		return false
	}
	_, ok := b.value[key]
	return ok
}

func (s MapValue) ToRego() interface{} {
	return map[string]interface{}{
		"filepath":  s.metadata.Range().GetFilename(),
		"startline": s.metadata.Range().GetStartLine(),
		"endline":   s.metadata.Range().GetEndLine(),
		"managed":   s.metadata.isManaged,
		"explicit":  s.metadata.isExplicit,
		"value":     s.Value(),
		"fskey":     CreateFSKey(s.metadata.Range().GetFS()),
		"resource":  s.metadata.Reference(),
	}
}
