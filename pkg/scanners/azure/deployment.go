package azure

import "github.com/aquasecurity/defsec/pkg/types"

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
	Tags       PropertyBag
	Sku        PropertyBag
	Properties PropertyBag
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
