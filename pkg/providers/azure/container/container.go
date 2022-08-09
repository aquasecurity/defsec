package container

import (
	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	types2.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        types2.BoolValue
	APIServerAuthorizedIPRanges []types2.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type AddonProfile struct {
	types2.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	types2.Metadata
	Enabled types2.BoolValue
}

type NetworkProfile struct {
	types2.Metadata
	NetworkPolicy types2.StringValue // "", "calico", "azure"
}
