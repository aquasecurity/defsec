package cloud

import (
	"context"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/state"
)

// Adapt ...
func Adapt(ctx context.Context, opt options.Options) (*state.State, error) {
	cloudState := &state.State{}
	err := aws.Adapt(ctx, cloudState, opt)
	return cloudState, err
}
