package convert

import (
	"reflect"
	"strings"
)

func StructToRego(inputValue reflect.Value) map[string]interface{} {

	// make sure we have a struct literal
	for inputValue.Type().Kind() == reflect.Ptr {
		if inputValue.IsNil() {
			return nil
		}
		inputValue = inputValue.Elem()
	}
	if inputValue.Type().Kind() != reflect.Struct {
		panic("not a struct")
	}

	output := make(map[string]interface{}, inputValue.NumField())

	for i := 0; i < inputValue.NumField(); i++ {
		field := inputValue.Field(i)
		typ := inputValue.Type().Field(i)
		name := typ.Name
		if !typ.IsExported() {
			continue
		}
		if field.Interface() == nil {
			continue
		}
		val := anonymousToRego(reflect.ValueOf(field.Interface()))
		if val == nil {
			continue
		}
		output[strings.ToLower(name)] = val
	}

	return output
}
