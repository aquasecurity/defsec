package emr

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	defsecTypes.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	defsecTypes.Metadata
	Name         defsecTypes.StringValue
	ReleaseLabel defsecTypes.StringValue
	ServiceRole  defsecTypes.StringValue
}

type SecurityConfiguration struct {
	defsecTypes.Metadata
	Name          defsecTypes.StringValue
	Configuration defsecTypes.StringValue
}
