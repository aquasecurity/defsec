package kms

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kms"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) kms.KMS{
	return kms.KMS{
		Keys: getKeys(cfFile),
	}
}
