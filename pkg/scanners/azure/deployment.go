package azure

import (
	"github.com/aquasecurity/defsec/pkg/types"
)

type Deployment struct {
	Metadata    types.Metadata
	TargetScope Scope
	Parameters  []Parameter
	Variables   []Variable
	Resources   []Resource
	Outputs     []Output
}

type Parameter struct {
	Variable
	Default    Value
	Decorators []Decorator
}

type Variable struct {
	Name  string
	Value Value
}

type Output Variable

type Resource struct {
	Metadata   types.Metadata
	APIVersion Value
	Type       Value
	Kind       Value
	Name       Value
	Location   Value
	Tags       Value
	Sku        Value
	Properties Value
	Resources  []Resource
}

type PropertyBag struct {
	Metadata types.Metadata
	Data     map[string]Value
}

type Decorator struct {
	Name string
	Args []Value
}

type Scope string

const (
	ScopeResourceGroup   Scope = "resourceGroup"
	ScopeSubscription    Scope = "subscription"
	ScopeTenant          Scope = "tenant"
	ScopeManagementGroup Scope = "managementGroup"
)

func (d *Deployment) GetResourcesByType(t string) []Resource {
	var resources []Resource
	for _, r := range d.Resources {
		if r.Type.AsString() == t {
			resources = append(resources, r)
		}
	}
	return resources
}

func (r *Resource) GetResourcesByType(t string) []Resource {
	var resources []Resource
	for _, res := range r.Resources {
		if res.Type.AsString() == t {
			resources = append(resources, res)
		}
	}
	return resources
}

func (d *Deployment) GetParameter(parameterName string) interface{} {

	for _, parameter := range d.Parameters {
		if parameter.Name == parameterName {
			return parameter.Value.Raw()
		}
	}
	return nil
}

func (d *Deployment) GetVariable(variableName string) interface{} {

	for _, variable := range d.Variables {
		if variable.Name == variableName {
			return variable.Value.Raw()
		}
	}
	return nil
}
