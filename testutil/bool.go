package testutil

import (
	"github.com/aquasecurity/defsec/definition"
)

type fakeRange struct {
}

func (f *fakeRange) GetFilename() string {
	return "main.tf"
}

func (f *fakeRange) GetModule() string {
	return "root"
}

func (f *fakeRange) GetStartLine() int {
	return 123
}

func (f *fakeRange) GetEndLine() int {
	return 123
}

func (f *fakeRange) Overlaps(a definition.Range) bool {
	return false
}

func (f *fakeRange) String() string {
	return "main.tf:123"
}

type fakeReference struct {
}

func (f *fakeReference) String() string {
	return "something.blah"
}

func (f *fakeReference) RefersTo(r definition.Reference) bool {
	return false
}

func NewBoolValue(val bool) definition.BoolValue {
	return definition.NewBoolValue(val, &fakeRange{}, &fakeReference{})
}
