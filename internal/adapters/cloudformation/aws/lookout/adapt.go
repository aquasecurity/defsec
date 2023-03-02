package lookout

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/lookout"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func getDetectors(ctx parser.FileContext) []lookout.AnomalyDetector {
	var detectors []lookout.AnomalyDetector
	for _, r := range ctx.GetResourcesByType("AWS::LookoutMetrics::AnomalyDetector") {
		detectors = append(detectors, lookout.AnomalyDetector{
			Metadata:  r.Metadata(),
			KmsKeyArn: r.GetStringProperty("kma_key_arn"),
		})
	}
	return detectors
}
