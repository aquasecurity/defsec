package elasticsearch

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	defsecTypes "github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/state"
	api "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
)

type adapter struct {
	*aws.RootAdapter
	api *api.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "elasticsearch"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Elasticsearch.Domains, err = a.getDomains()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getDomains() ([]elasticsearch.Domain, error) {

	a.Tracker().SetServiceLabel("Discovering domains...")

	var input api.ListDomainNamesInput
	output, err := a.api.ListDomainNames(a.Context(), &input)
	if err != nil {
		return nil, err
	}
	apiDomains := output.DomainNames
	a.Tracker().SetTotalResources(len(apiDomains))

	a.Tracker().SetServiceLabel("Adapting domains...")

	var domains []elasticsearch.Domain
	for _, apiDomain := range apiDomains {
		domain, err := a.adaptDomain(apiDomain)
		if err != nil {
			a.Debug("Failed to adapt domain '%s': %s", *apiDomain.DomainName, err)
			continue
		}
		domains = append(domains, *domain)
		a.Tracker().IncrementResource()
	}

	return domains, nil
}

func (a *adapter) adaptDomain(apiDomain types.DomainInfo) (*elasticsearch.Domain, error) {
	metadata := a.CreateMetadata(*apiDomain.DomainName)

	output, err := a.api.DescribeElasticsearchDomain(a.Context(), &api.DescribeElasticsearchDomainInput{
		DomainName: apiDomain.DomainName,
	})
	if err != nil {
		return nil, err
	}
	status := output.DomainStatus

	var auditEnabled bool
	var transitEncryption bool
	var atRestEncryption bool
	var enforceHTTPS bool
	var tlsPolicy string

	if status.LogPublishingOptions != nil {
		if audit, ok := status.LogPublishingOptions["AUDIT_LOGS"]; ok && audit.Enabled != nil {
			auditEnabled = *audit.Enabled
		}
	}

	if status.NodeToNodeEncryptionOptions != nil && status.NodeToNodeEncryptionOptions.Enabled != nil {
		transitEncryption = *status.NodeToNodeEncryptionOptions.Enabled
	}

	if status.EncryptionAtRestOptions != nil && status.EncryptionAtRestOptions.Enabled != nil {
		atRestEncryption = *status.EncryptionAtRestOptions.Enabled
	}

	if status.DomainEndpointOptions != nil {
		tlsPolicy = string(status.DomainEndpointOptions.TLSSecurityPolicy)
		if status.DomainEndpointOptions.EnforceHTTPS != nil {
			enforceHTTPS = *status.DomainEndpointOptions.EnforceHTTPS
		}
	}

	return &elasticsearch.Domain{
		Metadata:   metadata,
		DomainName: defsecTypes.String(*apiDomain.DomainName, metadata),
		LogPublishing: elasticsearch.LogPublishing{
			Metadata:     metadata,
			AuditEnabled: defsecTypes.Bool(auditEnabled, metadata),
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Metadata: metadata,
			Enabled:  defsecTypes.Bool(transitEncryption, metadata),
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Metadata: metadata,
			Enabled:  defsecTypes.Bool(atRestEncryption, metadata),
		},
		Endpoint: elasticsearch.Endpoint{
			Metadata:     metadata,
			EnforceHTTPS: defsecTypes.Bool(enforceHTTPS, metadata),
			TLSPolicy:    defsecTypes.String(tlsPolicy, metadata),
		},
	}, nil
}
