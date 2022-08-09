package container

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	defsecTypes.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        defsecTypes.BoolValue
	APIServerAuthorizedIPRanges []defsecTypes.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type AddonProfile struct {
	defsecTypes.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	defsecTypes.Metadata
	Enabled defsecTypes.BoolValue
}

type NetworkProfile struct {
	defsecTypes.Metadata
	NetworkPolicy defsecTypes.StringValue // "", "calico", "azure"
}
