package kinesisvideo

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesisvideo"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) kinesisvideo.Kinesisvideo {
	return kinesisvideo.Kinesisvideo{
		StreamInfoList: getStreamInfo(cfFile),
	}
}
