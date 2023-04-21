package kinesisvideo

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Kinesisvideo struct {
	StreamInfoList []StreamInfo
}

type StreamInfo struct {
	Metadata defsecTypes.Metadata
	KmsKeyId defsecTypes.StringValue
}
