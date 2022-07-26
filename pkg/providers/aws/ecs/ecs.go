package ecs

import (
	"encoding/json"

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
	ContainerDefinitions []ContainerDefinition
}

func CreateDefinitionsFromString(metadata types.Metadata, str string) ([]ContainerDefinition, error) {
	var containerDefinitionsJSON []containerDefinitionJSON
	if err := json.Unmarshal([]byte(str), &containerDefinitionsJSON); err != nil {
		return nil, err
	}
	var definitions []ContainerDefinition
	for _, j := range containerDefinitionsJSON {
		definitions = append(definitions, j.convert(metadata))
	}
	return definitions, nil
}

// see https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html
type containerDefinitionJSON struct {
	Name         string            `json:"name"`
	Image        string            `json:"image"`
	CPU          int               `json:"cpu"`
	Memory       int               `json:"memory"`
	Essential    bool              `json:"essential"`
	PortMappings []portMappingJSON `json:"portMappings"`
	EnvVars      []envVarJSON      `json:"environment"`
	Privileged   bool              `json:"privileged"`
}

type envVarJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type portMappingJSON struct {
	ContainerPort int `json:"containerPort"`
	HostPort      int `json:"hostPort"`
}

func (j containerDefinitionJSON) convert(metadata types.Metadata) ContainerDefinition {
	var mappings []PortMapping
	for _, jMapping := range j.PortMappings {
		mappings = append(mappings, PortMapping{
			ContainerPort: types.Int(jMapping.ContainerPort, metadata),
			HostPort:      types.Int(jMapping.HostPort, metadata),
		})
	}
	var envVars []EnvVar
	for _, env := range j.EnvVars {
		envVars = append(envVars, EnvVar(env))
	}
	return ContainerDefinition{
		Metadata:     metadata,
		Name:         types.String(j.Name, metadata),
		Image:        types.String(j.Image, metadata),
		CPU:          types.Int(j.CPU, metadata),
		Memory:       types.Int(j.Memory, metadata),
		Essential:    types.Bool(j.Essential, metadata),
		PortMappings: mappings,
		Environment:  envVars,
		Privileged:   types.Bool(j.Privileged, metadata),
	}
}

type ContainerDefinition struct {
	types.Metadata
	Name         types.StringValue
	Image        types.StringValue
	CPU          types.IntValue
	Memory       types.IntValue
	Essential    types.BoolValue
	PortMappings []PortMapping
	Environment  []EnvVar
	Privileged   types.BoolValue
}

type EnvVar struct {
	Name  string
	Value string
}

type PortMapping struct {
	ContainerPort types.IntValue
	HostPort      types.IntValue
}

type Volume struct {
	types.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	types.Metadata
	TransitEncryptionEnabled types.BoolValue
}
