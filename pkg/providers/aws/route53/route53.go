package route53

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Route53 struct {
	RecordSets []RecordSet
	Domains    []Domain
}

type RecordSet struct {
	Metadata        defsecTypes.Metadata
	Type            defsecTypes.StringValue
	Name            defsecTypes.StringValue
	ResourceRecords []defsecTypes.StringValue
	AliasTarget     AliasTarget
}

type AliasTarget struct {
	Metadata defsecTypes.Metadata
	DnsName  defsecTypes.StringValue
}

type Domain struct {
	Metadata          defsecTypes.Metadata
	Name              defsecTypes.StringValue
	AutoRenew         defsecTypes.BoolValue
	Expiry            defsecTypes.TimeValue
	RegistrantPrivacy defsecTypes.BoolValue
}
