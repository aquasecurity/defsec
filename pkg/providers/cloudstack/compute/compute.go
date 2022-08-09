package compute

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	types2.Metadata
	UserData types2.StringValue // not b64 encoded pls
}
