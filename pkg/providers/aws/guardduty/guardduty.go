package guardduty

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Guardduty struct {
	Detectors []Detector
}

type Detector struct {
	Metadata               defsecTypes.Metadata
	Status                 defsecTypes.BoolValue
	PublishingDestinations []PublishingDestination
	Findings               []Finding
	MasterAccount          MasterAccount
}

type PublishingDestination struct {
	Metadata  defsecTypes.Metadata
	KmsKeyArn defsecTypes.StringValue
}

type Finding struct {
	Metadata  defsecTypes.Metadata
	CreatedAt defsecTypes.StringValue
}

type MasterAccount struct {
	Metadata           defsecTypes.Metadata
	RelationshipStatus defsecTypes.StringValue
	AccountId          defsecTypes.StringValue
}
