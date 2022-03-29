package ec2

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type EC2 struct {
	types.Metadata
	Instances []Instance
}
