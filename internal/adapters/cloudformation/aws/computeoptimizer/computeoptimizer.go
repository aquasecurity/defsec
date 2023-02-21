package computeoptimizer

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/computeoptimizer"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) computeoptimizer.ComputeOptimizer {
	return computeoptimizer.ComputeOptimizer{
		RecommendationSummaries: nil,
	}
}
