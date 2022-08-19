package github

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type BranchProtection struct {
	defsecTypes.Metadata
	RequireSignedCommits defsecTypes.BoolValue
}

func (b BranchProtection) RequiresSignedCommits() bool {
	return b.RequireSignedCommits.IsTrue()
}
