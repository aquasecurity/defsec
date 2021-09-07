package ecs

import "github.com/aquasecurity/defsec/types"

type ECS struct {
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	*types.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	ContainerInsightsEnabled types.BoolValue
}

type TaskDefinition struct {
	*types.Metadata
	Volumes              []Volume
	ContainerDefinitions types.StringValue
}

type Volume struct {
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	TransitEncryptionEnabled types.BoolValue
}
