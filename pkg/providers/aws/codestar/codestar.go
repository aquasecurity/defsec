package codestar

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type CodeStar struct {
	Projects []Project
}

type Project struct {
	Metadata          defsecTypes.Metadata
	ProjectTemplateId defsecTypes.StringValue
}
