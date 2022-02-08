package rules

import (
	"github.com/aquasecurity/defsec/rules"
)

// Rule ...
type Rule struct {
	Base rules.RegisteredRule

	// BadExample (yaml) contains CloudFormation code which would cause the check to fail
	BadExample []string

	// GoodExample (yaml) contains CloudFormation code which would pass the check
	GoodExample []string

	// Additional links for further reading about the check
	Links []string
}

// ID ...
func (r Rule) ID() string {
	return r.Base.Rule().AVDID
}

func (r Rule) LongID() string {
	return r.Base.Rule().LongID()
}
