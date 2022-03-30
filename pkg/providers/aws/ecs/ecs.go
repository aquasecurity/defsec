package ecs

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type ECS struct {
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	types.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	types.Metadata
	ContainerInsightsEnabled types.BoolValue
}

type TaskDefinition struct {
	types.Metadata
	Volumes              []Volume
	ContainerDefinitions types.StringValue
}

type Volume struct {
	types.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	types.Metadata
	TransitEncryptionEnabled types.BoolValue
}
