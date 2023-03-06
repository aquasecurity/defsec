package xray

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/xray"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) xray.Xray {
	var keyId xray.Configuration // no encryption configuration docs in cloudformation.
	return xray.Xray{
		EncryptionConfig: keyId,
	}
}
