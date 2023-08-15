package azure

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	//"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/errs"
	//"github.com/aquasecurity/defsec/pkg/types"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/aquasecurity/defsec/internal/adapters/cloud/options"
	"github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/progress"
	"github.com/aquasecurity/defsec/pkg/state"
	//"github.com/aws/aws-sdk-go-v2/service/sts"
)

var registeredAdapters []ServiceAdapter
var Token string

func RegisterServiceAdapter(adapter ServiceAdapter) {
	for _, existing := range registeredAdapters {
		if existing.Name() == adapter.Name() {
			panic(fmt.Sprintf("duplicate service adapter: %s", adapter.Name()))
		}
	}
	registeredAdapters = append(registeredAdapters, adapter)
}

type ServiceAdapter interface {
	Name() string
	Provider() string
	Adapt(root *RootAdapter, state *state.State) error
}

type RootAdapter struct {
	ctx                 context.Context
	tracker             progress.ServiceTracker
	accountID           string
	currentService      string
	location            string
	debugWriter         debug.Logger
	concurrencyStrategy concurrency.Strategy
}

func NewRootAdapter(ctx context.Context, tracker progress.ServiceTracker) *RootAdapter {
	return &RootAdapter{
		ctx:     ctx,
		tracker: tracker,
		//location:   cfg.Region,
	}
}

func (a *RootAdapter) Location() string {
	return a.location
}

func (a *RootAdapter) Debug(format string, args ...interface{}) {
	a.debugWriter.Log(format, args...)
}

func (a *RootAdapter) ConcurrencyStrategy() concurrency.Strategy {
	return a.concurrencyStrategy
}

func (a *RootAdapter) Context() context.Context {
	return a.ctx
}

func (a *RootAdapter) Tracker() progress.ServiceTracker {
	return a.tracker
}

/*func (a *RootAdapter) CreateMetadata(resource string) types.Metadata {

	// some services don't require region/account id in the ARN
	// see https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces
	namespace := a.accountID
	location := a.location
	switch a.currentService {
	case "compute":
		namespace = ""
		location = ""
	}

	return a.CreateMetadataFromARN((arn.ARN{
		Partition: "azure",
		Service:   a.currentService,
		Location:  location,
		AccountID: namespace,
		Resource:  resource,
	}).String())
}

func (a *RootAdapter) CreateMetadataFromARN(arn string) types.Metadata {
	return types.NewRemoteMetadata(arn)
}

/*type resolver struct {
	endpoint string
}

func (r *resolver) ResolveEndpoint(_, _ string, _ ...interface{}) (azure.Endpoint, error) {
	return azure.Endpoint{
		URL:           r.endpoint,
		SigningRegion: "custom-signing-region",
		Source:        aws.EndpointSourceCustom,
	}, nil


func createResolver(endpoint string) aws.EndpointResolverWithOptions {
	return &resolver{
		endpoint: endpoint,
	}
}*/

func AllServices() []string {
	var services []string
	for _, reg := range registeredAdapters {
		services = append(services, reg.Name())
	}
	return services
}

func Adapt(ctx context.Context, state *state.State, opt *options.AZUREOptions) error {
	c := &RootAdapter{
		ctx:                 ctx,
		tracker:             opt.ProgressTracker,
		debugWriter:         opt.DebugWriter.Extend("adapt", "azure"),
		concurrencyStrategy: opt.ConcurrencyStrategy,
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return err
	}

	const scope = "https://management.azure.com/.default"

	if err != nil {
		fmt.Errorf("unable to get an access token: %w", err)
	}
	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	Token = aadToken.Token

	/*if opt.Location != "" {
		c.Debug("Using location '%s'", opt.Location)
		c.sessionCfg.Location = opt.Location
	}
	if opt.Endpoint != "" {
		c.Debug("Using endpoint '%s'", opt.Endpoint)
		c.sessionCfg.EndpointResolverWithOptions = createResolver(opt.Endpoint)
	}*/

	c.Debug("Discovering caller identity...")
	//stsClient := sts.NewFromConfig(c.sessionCfg.)
	//result, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to discover AZURE caller identity: %w", err)
	}
	//if result.Account == nil {
	//	return fmt.Errorf("missing account id for aws account")
	//}
	//c.accountID = *result.Account
	//c.Debug("AWS account ID: %s", c.accountID)

	if len(opt.Services) == 0 {
		c.Debug("Preparing to run for all %d registered services...", len(registeredAdapters))
		opt.ProgressTracker.SetTotalServices(len(registeredAdapters))
	} else {
		c.Debug("Preparing to run for %d filtered services...", len(opt.Services))
		opt.ProgressTracker.SetTotalServices(len(opt.Services))
	}

	//c.location = c.sessionCfg.Region

	var adapterErrors []error

	for _, adapter := range registeredAdapters {
		if len(opt.Services) != 0 && !contains(opt.Services, adapter.Name()) {
			continue
		}
		c.currentService = adapter.Name()
		c.Debug("Running adapter for %s...", adapter.Name())
		opt.ProgressTracker.StartService(adapter.Name())

		if err := adapter.Adapt(c, state); err != nil {
			c.Debug("Error occurred while running adapter for %s: %s", adapter.Name(), err)
			adapterErrors = append(adapterErrors, fmt.Errorf("failed to run adapter for %s: %w", adapter.Name(), err))
		}
		opt.ProgressTracker.FinishService()
	}

	if len(adapterErrors) > 0 {
		return errs.NewAdapterError(adapterErrors)
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

func GetToken() string {
	return Token
}
