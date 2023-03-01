package guardduty

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/guardduty"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/aquasecurity/defsec/pkg/types"
)

func getDetectors(ctx parser.FileContext) []guardduty.Detector {

	resources := ctx.GetResourcesByType("AWS::GuardDuty::Detector")
	var detectors []guardduty.Detector
	for _, r := range resources {
		detectors = append(detectors, guardduty.Detector{
			Metadata:               r.Metadata(),
			Status:                 r.GetBoolProperty("Enable"),
			PublishingDestinations: nil,
			Findings:               nil,
			MasterAccount:          getAccounts(ctx),
		})
	}
	return detectors
}

func getAccounts(ctx parser.FileContext) guardduty.MasterAccount {
	var accounts guardduty.MasterAccount
	for _, r := range ctx.GetResourcesByType("AWS::GuardDuty::Master") {
		accounts = guardduty.MasterAccount{
			Metadata:           r.Metadata(),
			RelationshipStatus: types.String("", r.Metadata()),
			AccountId:          r.GetStringProperty("MasterId"),
		}
	}
	return accounts
}
