package aws

import (
	"context"
	"fmt"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
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
	ctx            context.Context
	sessionCfg     aws.Config
	tracker        progress.ServiceTracker
	accountID      string
	currentService string
	region         string
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

func (a *RootAdapter) CreateMetadata(resource string) types.Metadata {

	// some services don't require region/account id in the ARN
	// see https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces
	namespace := a.accountID
	region := a.region
	switch a.currentService {
	case "s3":
		namespace = ""
		region = ""
	}

	return a.CreateMetadataFromARN((arn.ARN{
		Partition: "aws",
		Service:   a.currentService,
		Region:    region,
		AccountID: namespace,
		Resource:  resource,
	}).String())
}

func (a *RootAdapter) CreateMetadataFromARN(arn string) types.Metadata {
	return types.NewRemoteMetadata(arn)
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

	stsClient := sts.NewFromConfig(c.sessionCfg)
	result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to discover AWS caller identity: %w", err)
	}
	if result.Account == nil {
		return fmt.Errorf("missing account id for aws account")
	}
	c.accountID = *result.Account

	if len(opt.Services) == 0 {
		opt.ProgressTracker.SetTotalServices(len(registeredAdapters))
	} else {
		opt.ProgressTracker.SetTotalServices(len(opt.Services))
	}

	c.region = c.sessionCfg.Region

	for _, adapter := range registeredAdapters {
		if len(opt.Services) != 0 && !contains(opt.Services, adapter.Name()) {
			continue
		}
		c.currentService = adapter.Name()
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
