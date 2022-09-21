package types

type Source string

const (
	SourceDockerfile Source = "dockerfile"
	SourceKubernetes Source = "kubernetes"
	SourceRbac       Source = "rbac"
	SourceDefsec     Source = "defsec"
	SourceYAML       Source = "yaml"
	SourceJSON       Source = "json"
	SourceTOML       Source = "toml"
)
