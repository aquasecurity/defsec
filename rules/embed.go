package rules

import (
	"embed"
)

//go:embed docker/lib docker/policies kubernetes/lib kubernetes/policies
var EmbeddedPolicyFileSystem embed.FS
