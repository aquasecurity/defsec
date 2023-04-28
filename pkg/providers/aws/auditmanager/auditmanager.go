package auditmanager

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type AuditManager struct {
	Settings Setting
}

type Setting struct {
	Metadata defsecTypes.Metadata
	KmsKey   defsecTypes.StringValue
}
