package computeoptimizer

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type ComputeOptimizer struct {
	RecommendationSummaries []RecommendationSummary
}

type RecommendationSummary struct {
	Metadata     defsecTypes.Metadata
	ResourceType defsecTypes.StringValue
	Summaries    []Summary
}

type Summary struct {
	Metadata defsecTypes.Metadata
	Name     defsecTypes.StringValue
	Value    defsecTypes.IntValue
}
