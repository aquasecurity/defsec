package elasticsearch

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/elasticsearch"
	"github.com/aquasecurity/defsec/pkg/scanners/aws/cloudformation/parser"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

func getDomains(ctx parser.FileContext) (domains []elasticsearch.Domain) {

	domainResources := ctx.GetResourcesByType("AWS::Elasticsearch::Domain", "AWS::OpenSearchService::Domain")

	for _, r := range domainResources {

		domain := elasticsearch.Domain{
			Metadata:   r.Metadata(),
			DomainName: r.GetStringProperty("DomainName"),
			LogPublishing: elasticsearch.LogPublishing{
				Metadata:     r.Metadata(),
				AuditEnabled: defsecTypes.BoolDefault(false, r.Metadata()),
			},
			TransitEncryption: elasticsearch.TransitEncryption{
				Metadata: r.Metadata(),
				Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
			},
			AtRestEncryption: elasticsearch.AtRestEncryption{
				Metadata: r.Metadata(),
				Enabled:  defsecTypes.BoolDefault(false, r.Metadata()),
			},
			Endpoint: elasticsearch.Endpoint{
				Metadata:     r.Metadata(),
				EnforceHTTPS: defsecTypes.BoolDefault(false, r.Metadata()),
				TLSPolicy:    defsecTypes.StringDefault("Policy-Min-TLS-1-0-2019-07", r.Metadata()),
			},
		}

		if prop := r.GetProperty("LogPublishingOptions"); prop.IsNotNil() {
			domain.LogPublishing = elasticsearch.LogPublishing{
				Metadata:     prop.Metadata(),
				AuditEnabled: prop.GetBoolProperty("AUDIT_LOGS.Enabled", false),
			}
		}

		if prop := r.GetProperty("NodeToNodeEncryptionOptions"); prop.IsNotNil() {
			domain.TransitEncryption = elasticsearch.TransitEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled", false),
			}
		}

		if prop := r.GetProperty("EncryptionAtRestOptions"); prop.IsNotNil() {
			domain.AtRestEncryption = elasticsearch.AtRestEncryption{
				Metadata: prop.Metadata(),
				Enabled:  prop.GetBoolProperty("Enabled", false),
			}
		}

		if prop := r.GetProperty("DomainEndpointOptions"); prop.IsNotNil() {
			domain.Endpoint = elasticsearch.Endpoint{
				Metadata:     prop.Metadata(),
				EnforceHTTPS: prop.GetBoolProperty("EnforceHTTPS", false),
				TLSPolicy:    prop.GetStringProperty("TLSSecurityPolicy", "Policy-Min-TLS-1-0-2019-07"),
			}
		}

		domains = append(domains, domain)
	}

	return domains
}
