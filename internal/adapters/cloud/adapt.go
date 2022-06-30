package cloud

import (
	"context"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/state"
)

// Adapt ...
func Adapt(ctx context.Context, progress progress.Tracker) (*state.State, error) {

	cloudState := &state.State{}
	if err := aws.Adapt(ctx, cloudState, progress); err != nil {
		return nil, err
	}

	return cloudState, nil
}
