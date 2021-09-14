package cloudwatch

import "github.com/aquasecurity/defsec/types"

type CloudWatch struct {
	LogGroups []LogGroup
}

type LogGroup struct {
	Name     types.StringValue
	KMSKeyID types.StringValue
}
