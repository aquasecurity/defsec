package route53

import (
	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/concurrency"
	"github.com/aquasecurity/defsec/pkg/providers/aws/route53"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	api "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	domainapi "github.com/aws/aws-sdk-go-v2/service/route53domains"
	domaintypes "github.com/aws/aws-sdk-go-v2/service/route53domains/types"
)

type adapter struct {
	*aws.RootAdapter
	api       *api.Client
	domainapi *domainapi.Client
}

func init() {
	aws.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "route53"
}

func (a *adapter) Adapt(root *aws.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = api.NewFromConfig(root.SessionConfig())
	a.domainapi = domainapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.Route53.RecordSets, err = a.getRecordSets()
	if err != nil {
		return err
	}

	state.AWS.Route53.Domains, err = a.getDomains()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getRecordSets() ([]route53.RecordSet, error) {

	a.Tracker().SetServiceLabel("Discovering record sets...")

	var apiRecords []types.ResourceRecordSet
	var input api.ListHostedZonesInput
	output, err := a.api.ListHostedZones(a.Context(), &input)
	if err != nil {
		return nil, err
	}

	for _, zone := range output.HostedZones {
		record, err := a.api.ListResourceRecordSets(a.Context(), &api.ListResourceRecordSetsInput{
			HostedZoneId: zone.Id,
		})
		if err != nil {
			return nil, err
		}
		apiRecords = append(apiRecords, record.ResourceRecordSets...)
		a.Tracker().SetTotalResources(len(apiRecords))
		if output.Marker == nil {
			break
		}
		input.Marker = output.Marker

	}

	a.Tracker().SetServiceLabel("Adapting record set...")
	return concurrency.Adapt(apiRecords, a.RootAdapter, a.adaptRecordSet), nil
}

func (a *adapter) adaptRecordSet(record types.ResourceRecordSet) (*route53.RecordSet, error) {
	metadata := a.CreateMetadata(*record.Name)

	var dnsname string
	if record.AliasTarget != nil {
		dnsname = *record.AliasTarget.DNSName
	}

	var records []defsecTypes.StringValue
	for _, r := range record.ResourceRecords {
		records = append(records, defsecTypes.String(*r.Value, metadata))
	}

	return &route53.RecordSet{
		Metadata:        metadata,
		Name:            defsecTypes.String(*record.Name, metadata),
		Type:            defsecTypes.String(string(record.Type), metadata),
		ResourceRecords: records,
		AliasTarget: route53.AliasTarget{
			Metadata: metadata,
			DnsName:  defsecTypes.String(dnsname, metadata),
		},
	}, nil
}

func (a *adapter) getDomains() ([]route53.Domain, error) {

	a.Tracker().SetServiceLabel("Discovering domains...")

	var apiDomains []domaintypes.DomainSummary
	var input domainapi.ListDomainsInput
	for {
		output, err := a.domainapi.ListDomains(a.Context(), &input)
		if err != nil {
			return nil, err
		}
		apiDomains = append(apiDomains, output.Domains...)
		a.Tracker().SetTotalResources(len(apiDomains))
		if output.NextPageMarker == nil {
			break
		}

	}

	a.Tracker().SetServiceLabel("Adapting domain...")
	return concurrency.Adapt(apiDomains, a.RootAdapter, a.adaptDomain), nil
}

func (a *adapter) adaptDomain(domain domaintypes.DomainSummary) (*route53.Domain, error) {
	metadata := a.CreateMetadata(*domain.DomainName)

	output, err := a.domainapi.GetDomainDetail(a.Context(), &domainapi.GetDomainDetailInput{
		DomainName: domain.DomainName,
	})
	if err != nil {
		return nil, err
	}

	return &route53.Domain{
		Metadata:          metadata,
		Name:              defsecTypes.String(*domain.DomainName, metadata),
		AutoRenew:         defsecTypes.Bool(*domain.AutoRenew, metadata),
		Expiry:            defsecTypes.Time(*domain.Expiry, metadata),
		RegistrantPrivacy: defsecTypes.Bool(*output.RegistrantPrivacy, metadata),
	}, nil
}
