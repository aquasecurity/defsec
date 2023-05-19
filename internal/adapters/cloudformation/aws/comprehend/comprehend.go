package comprehend

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/comprehend"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

func Adapt(cfFile parser.FileContext) comprehend.Comprehend {
	return comprehend.Comprehend{
		EntitiesDetectionJobs:         nil,
		DominantLanguageDetectionJobs: nil,
		TopicsDetectionJobs:           nil,
		SentimentDetectionJobs:        nil,
		KeyPhrasesDetectionJobs:       nil,
		DocumentClassificationJobs:    nil,
	}
}
