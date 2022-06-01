package emr

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	types.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	types.Metadata
	Name         types.StringValue
	ReleaseLabel types.StringValue
	ServiceRole  types.StringValue
}

type SecurityConfiguration struct {
	types.Metadata
	Name          types.StringValue
	Configuration types.StringValue
}
