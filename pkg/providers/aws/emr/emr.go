package emr

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	types2.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	types2.Metadata
	Name         types2.StringValue
	ReleaseLabel types2.StringValue
	ServiceRole  types2.StringValue
}

type SecurityConfiguration struct {
	types2.Metadata
	Name          types2.StringValue
	Configuration types2.StringValue
}
