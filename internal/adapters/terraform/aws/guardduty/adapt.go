package guardduty

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/guardduty"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
)

func Adapt(modules terraform.Modules) guardduty.Guardduty {
	return guardduty.Guardduty{
		Detectors: adaptDetectors(modules),
	}
}

func adaptDetectors(modules terraform.Modules) []guardduty.Detector {
	var detectors []guardduty.Detector
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_guardduty_detector") {
			detectors = append(detectors, adaptDetector(resource, module))
		}
	}
	return detectors
}

func adaptDetector(resource *terraform.Block, module *terraform.Module) guardduty.Detector {
	var destinations []guardduty.PublishingDestination
	for _, d := range module.GetReferencingResources(resource, "aws_guardduty_publishing_destination", "detector_id") {
		destinations = append(destinations, guardduty.PublishingDestination{
			Metadata:  d.GetMetadata(),
			KmsKeyArn: d.GetAttribute("kms_key_arn").AsStringValueOrDefault("", d),
		})
	}

	var account guardduty.MasterAccount
	for _, a := range module.GetResourcesByType("aws_guardduty_organization_admin_account") {
		account = guardduty.MasterAccount{
			Metadata:           a.GetMetadata(),
			RelationshipStatus: types.String("", a.GetMetadata()),
			AccountId:          a.GetAttribute("admin_account_id").AsStringValueOrDefault("", a),
		}
	}
	return guardduty.Detector{
		Metadata:               resource.GetMetadata(),
		Status:                 resource.GetAttribute("enable").AsBoolValueOrDefault(true, resource),
		Findings:               nil,
		PublishingDestinations: destinations,
		MasterAccount:          account,
	}
}
