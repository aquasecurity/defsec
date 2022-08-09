package parser

import (
	"fmt"

	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type CFReference struct {
	logicalId     string
	resourceRange types2.Range
	resolvedValue Property
}

func NewCFReference(id string, resourceRange types2.Range) types2.Reference {
	return &CFReference{
		logicalId:     id,
		resourceRange: resourceRange,
	}
}

func NewCFReferenceWithValue(resourceRange types2.Range, resolvedValue Property, logicalId string) types2.Reference {
	return &CFReference{
		resourceRange: resourceRange,
		resolvedValue: resolvedValue,
		logicalId:     logicalId,
	}
}

func (cf *CFReference) String() string {
	return cf.resourceRange.String()
}

func (cf *CFReference) LogicalID() string {
	return cf.logicalId
}

func (cf *CFReference) RefersTo(r types2.Reference) bool {
	return false
}

func (cf *CFReference) ResourceRange() types2.Range {
	return cf.resourceRange
}

func (cf *CFReference) PropertyRange() types2.Range {
	if cf.resolvedValue.IsNotNil() {
		return cf.resolvedValue.Range()
	}
	return nil
}

func (cf *CFReference) DisplayValue() string {
	if cf.resolvedValue.IsNotNil() {
		return fmt.Sprintf("%v", cf.resolvedValue.RawValue())
	}
	return ""
}

func (cf *CFReference) Comment() string {
	return cf.resolvedValue.Comment()
}
