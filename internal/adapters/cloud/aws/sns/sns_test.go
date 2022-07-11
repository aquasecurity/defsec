package sns

import (
	"fmt"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aws/aws-sdk-go-v2/aws"
	snsapi "github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
)

type topicDetails struct {
	topicName string
	kmsKeyID  string
}

func (q topicDetails) TopicARN() string {
	return fmt.Sprintf("arn:aws:sns:us-east-1:000000000000:%s", q.topicName)
}

func Test_SNSTopicEncryption(t *testing.T) {

	tests := []struct {
		name    string
		details topicDetails
	}{
		{
			name: "simple queue with no encryption",
			details: topicDetails{
				topicName: "test-topic",
			},
		},
		{
			name: "simple queue with encryption",
			details: topicDetails{
				topicName: "test-encrypted-topic",
				kmsKeyID:  "alias/sns",
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapSNSTopic(t, ra, tt.details)

			testState := &state.State{}
			adapter := &adapter{}
			err = adapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.SNS.Topics, 1)
			var got sns.Topic
			for _, q := range testState.AWS.SNS.Topics {
				if q.TopicARN.EqualTo(tt.details.TopicARN()) {
					got = q
					break
				}
			}

			assert.Equal(t, tt.details.TopicARN(), got.TopicARN.Value())
			assert.Equal(t, tt.details.kmsKeyID, got.Encryption.KMSKeyID.Value())
			removeTopic(t, ra, tt.details.TopicARN())
		})
	}
}

func bootstrapSNSTopic(t *testing.T, ra *aws2.RootAdapter, spec topicDetails) {

	api := snsapi.NewFromConfig(ra.SessionConfig())

	topicAttributes := make(map[string]string)
	if spec.kmsKeyID != "" {
		topicAttributes["KmsMasterKeyId"] = spec.kmsKeyID
	}

	_, err := api.CreateTopic(ra.Context(), &snsapi.CreateTopicInput{
		Name:       aws.String(spec.topicName),
		Attributes: topicAttributes,
	})
	require.NoError(t, err)

}

func removeTopic(t *testing.T, ra *aws2.RootAdapter, topicARN string) {

	api := snsapi.NewFromConfig(ra.SessionConfig())

	_, err := api.DeleteTopic(ra.Context(), &snsapi.DeleteTopicInput{
		TopicArn: aws.String(topicARN),
	})
	require.NoError(t, err)
}
