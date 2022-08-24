package compute

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	defsecTypes.Metadata
	UserData defsecTypes.StringValue // not b64 encoded pls
}
