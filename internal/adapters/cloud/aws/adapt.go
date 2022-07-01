package aws

import (
	"context"

	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/state"
	aws2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

var registeredAdapters []ServiceAdapter

func RegisterServiceAdapter(adapter ServiceAdapter) {
	registeredAdapters = append(registeredAdapters, adapter)
}

type ServiceAdapter interface {
	Name() string
	Adapt(root *RootAdapter, state *state.State) error
}

type RootAdapter struct {
	ctx        context.Context
	sessionCfg aws2.Config
	tracker    progress.ServiceTracker
}

func (a *RootAdapter) SessionConfig() aws2.Config {
	return a.sessionCfg
}

func (a *RootAdapter) Context() context.Context {
	return a.ctx
}

func (a *RootAdapter) Tracker() progress.ServiceTracker {
	return a.tracker
}

func Adapt(ctx context.Context, state *state.State, tracker progress.Tracker) error {
	c := &RootAdapter{
		ctx:     ctx,
		tracker: tracker,
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	c.sessionCfg = cfg

	tracker.SetTotalServices(len(registeredAdapters))

	for _, adapter := range registeredAdapters {
		tracker.StartService(adapter.Name())
		if err := adapter.Adapt(c, state); err != nil {
			return err
		}
		tracker.FinishService()
	}
	return nil
}
