package github

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Repository struct {
	types2.Metadata
	Public              types2.BoolValue
	VulnerabilityAlerts types2.BoolValue
	Archived            types2.BoolValue
}

func (r Repository) IsArchived() bool {
	return r.Archived.IsTrue()
}
