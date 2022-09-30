package arm

import (
	"context"

	"github.com/aquasecurity/defsec/pkg/providers/azure"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/azure"
	"github.com/aquasecurity/defsec/pkg/state"
)

// Adapt ...
func Adapt(ctx context.Context, deployment scanner.Deployment) *state.State {
	return &state.State{
		Azure: adaptAzure(deployment),
	}
}

func adaptAzure(deployment scanner.Deployment) azure.Azure {
	return azure.Azure{
	}
}
