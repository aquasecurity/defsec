package comprehend

import (
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Comprehend struct {
	EntitiesDetectionJobs         []EntitiesDetectionJob
	DominantLanguageDetectionJobs []DominantLanguageDetectionJob
	TopicsDetectionJobs           []TopicsDetectionJob
	SentimentDetectionJobs        []SentimentDetectionJob
	KeyPhrasesDetectionJobs       []KeyPhrasesDetectionJob
	DocumentClassificationJobs    []DocumentClassificationJob
}

type EntitiesDetectionJob struct {
	Metadata       defsecTypes.Metadata
	VolumeKmsKeyId defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}

type DominantLanguageDetectionJob struct {
	Metadata       defsecTypes.Metadata
	VolumeKmsKeyId defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}

type TopicsDetectionJob struct {
	Metadata       defsecTypes.Metadata
	VolumeKmsKeyId defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}

type SentimentDetectionJob struct {
	Metadata       defsecTypes.Metadata
	VolumeKmsKeyId defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}

type KeyPhrasesDetectionJob struct {
	Metadata       defsecTypes.Metadata
	VolumeKmsKeyId defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}

type DocumentClassificationJob struct {
	Metadata       defsecTypes.Metadata
	VolumeKmsKeyId defsecTypes.StringValue
	KmsKeyId       defsecTypes.StringValue
}
