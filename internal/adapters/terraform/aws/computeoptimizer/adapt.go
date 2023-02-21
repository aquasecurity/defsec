package computeoptimizer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/computeoptimizer"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) computeoptimizer.ComputeOptimizer {
	return computeoptimizer.ComputeOptimizer{
		RecommendationSummaries: nil,
	}
}
