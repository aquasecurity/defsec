package dns

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/dns"
	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/aquasecurity/defsec/internal/rules"

	"github.com/aquasecurity/defsec/pkg/providers"
)

var CheckRemoveVerifiedRecord = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0007",
		Provider:   providers.NifcloudProvider,
		Service:    "dns",
		ShortCode:  "remove-verified-record",
		Summary:    "Delete verified record",
		Impact:     "Risk of DNS records be used by others",
		Resolution: "Remove verified record",
		Explanation: `
Removing verified record of TXT auth the risk that 
If the authentication record remains, anyone can register the zone`,
		Links: []string{
			"https://pfs.nifcloud.com/guide/dns/zone_new.htm",
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, record := range s.Nifcloud.DNS.Records {
			if record.Type.EqualTo("TXT") && record.Record.StartsWith(dns.ZoneRegistrationAuthTxt) {
				results.Add("Authentication TXT record exists.", &record)
			} else {
				results.AddPassed(&record)
			}
		}
		return
	},
)
