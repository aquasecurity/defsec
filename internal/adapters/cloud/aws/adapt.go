package aws

import (
	"context"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

var registeredAdapters []ServiceAdapter

func RegisterServiceAdapter(adapter ServiceAdapter) {
	registeredAdapters = append(registeredAdapters, adapter)
}

type ServiceAdapter interface {
	Name() string
	Provider() string
	Adapt(root *RootAdapter, state *state.State) error
}

type RootAdapter struct {
	ctx        context.Context
	sessionCfg aws.Config
	tracker    progress.ServiceTracker
}

func (a *RootAdapter) SessionConfig() aws.Config {
	return a.sessionCfg
}

func (a *RootAdapter) Context() context.Context {
	return a.ctx
}

func (a *RootAdapter) Tracker() progress.ServiceTracker {
	return a.tracker
}

type resolver struct {
	endpoint string
}

func (r *resolver) ResolveEndpoint(_, _ string, _ ...interface{}) (aws.Endpoint, error) {
	return aws.Endpoint{
		URL:           r.endpoint,
		SigningRegion: "custom-signing-region",
		Source:        aws.EndpointSourceCustom,
	}, nil
}

func createResolver(endpoint string) aws.EndpointResolverWithOptions {
	return &resolver{
		endpoint: endpoint,
	}
}

func AllServices() []string {
	var services []string
	for _, reg := range registeredAdapters {
		services = append(services, reg.Name())
	}
	return services
}

func Adapt(ctx context.Context, state *state.State, opt options.Options) error {
	c := &RootAdapter{
		ctx:     ctx,
		tracker: opt.ProgressTracker,
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	c.sessionCfg = cfg

	if opt.Region != "" {
		c.sessionCfg.Region = opt.Region
	}
	if opt.Endpoint != "" {
		c.sessionCfg.EndpointResolverWithOptions = createResolver(opt.Endpoint)
	}

	if len(opt.Services) == 0 {
		opt.ProgressTracker.SetTotalServices(len(registeredAdapters))
	} else {
		opt.ProgressTracker.SetTotalServices(len(opt.Services))
	}

	for _, adapter := range registeredAdapters {
		if len(opt.Services) != 0 && !contains(opt.Services, adapter.Name()) {
			continue
		}
		opt.ProgressTracker.StartService(adapter.Name())
		if err := adapter.Adapt(c, state); err != nil {
			return err
		}
		opt.ProgressTracker.FinishService()
	}
	return nil
}

func contains(services []string, service string) bool {
	for _, s := range services {
		if s == service {
			return true
		}
	}
	return false
}
