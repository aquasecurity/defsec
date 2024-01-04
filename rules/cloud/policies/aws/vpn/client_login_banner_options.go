package vpn

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckClientLoginBannerOptions = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0345",
		Provider:    providers.AWSProvider,
		Service:     "vpn",
		ShortCode:   "client_login_banner_options",
		Summary:     "Client VPN should display login banner messages",
		Impact:      "Missing client login banners or messages will fail an audit",
		Resolution:  "Enable client login banner messages",
		Explanation: `System use notifications can be implemented using messages or warning banners displayed before individuals log in to systems`,
		Links: []string{
			"https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/what-is.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformCheckClientLoginBannerOptionsGoodExamples,
			BadExamples:         terraformCheckClientLoginBannerOptionsBadExamples,
			Links:               terraformCheckClientLoginBannerOptionsLinks,
			RemediationMarkdown: terraformCheckClientLoginBannerOptionsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, vpn := range s.AWS.VPN.Vpns {
			if vpn.BannerOptions.IsEmpty() {
				results.Add(
					"VPN does not display client login banner message.",
					vpn.BannerOptions,
				)
			} else {
				results.AddPassed(&vpn)
			}
		}
		return
	},
)
