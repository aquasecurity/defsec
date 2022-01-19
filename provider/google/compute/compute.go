package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	types.Metadata
	Disks           []Disk
	Networks        []Network
	SSLPolicies     []SSLPolicy
	ProjectMetadata ProjectMetadata
	Instances       []Instance
}
