package github

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type GitHub struct {
	types.Metadata
	Repositories       []Repository
	EnvironmentSecrets []EnvironmentSecret
}
