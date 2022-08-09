package ecs

import (
	"encoding/json"

	types2 "github.com/aquasecurity/defsec/pkg/types"
)

type ECS struct {
	Clusters        []Cluster
	TaskDefinitions []TaskDefinition
}

type Cluster struct {
	types2.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	types2.Metadata
	ContainerInsightsEnabled types2.BoolValue
}

type TaskDefinition struct {
	types2.Metadata
	Volumes              []Volume
	ContainerDefinitions []ContainerDefinition
}

func CreateDefinitionsFromString(metadata types2.Metadata, str string) ([]ContainerDefinition, error) {
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

func (j containerDefinitionJSON) convert(metadata types2.Metadata) ContainerDefinition {
	var mappings []PortMapping
	for _, jMapping := range j.PortMappings {
		mappings = append(mappings, PortMapping{
			ContainerPort: types2.Int(jMapping.ContainerPort, metadata),
			HostPort:      types2.Int(jMapping.HostPort, metadata),
		})
	}
	var envVars []EnvVar
	for _, env := range j.EnvVars {
		envVars = append(envVars, EnvVar(env))
	}
	return ContainerDefinition{
		Metadata:     metadata,
		Name:         types2.String(j.Name, metadata),
		Image:        types2.String(j.Image, metadata),
		CPU:          types2.Int(j.CPU, metadata),
		Memory:       types2.Int(j.Memory, metadata),
		Essential:    types2.Bool(j.Essential, metadata),
		PortMappings: mappings,
		Environment:  envVars,
		Privileged:   types2.Bool(j.Privileged, metadata),
	}
}

type ContainerDefinition struct {
	types2.Metadata
	Name         types2.StringValue
	Image        types2.StringValue
	CPU          types2.IntValue
	Memory       types2.IntValue
	Essential    types2.BoolValue
	PortMappings []PortMapping
	Environment  []EnvVar
	Privileged   types2.BoolValue
}

type EnvVar struct {
	Name  string
	Value string
}

type PortMapping struct {
	ContainerPort types2.IntValue
	HostPort      types2.IntValue
}

type Volume struct {
	types2.Metadata
	EFSVolumeConfiguration EFSVolumeConfiguration
}

type EFSVolumeConfiguration struct {
	types2.Metadata
	TransitEncryptionEnabled types2.BoolValue
}
