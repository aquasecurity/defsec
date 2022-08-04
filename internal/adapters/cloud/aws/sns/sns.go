package sns

import (
	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/aquasecurity/defsec/pkg/state"
	snsapi "github.com/aws/aws-sdk-go-v2/service/sns"
)

type adapter struct {
	*aws2.RootAdapter
	api *snsapi.Client
}

func init() {
	aws2.RegisterServiceAdapter(&adapter{})
}

func (a *adapter) Provider() string {
	return "aws"
}

func (a *adapter) Name() string {
	return "sns"
}

func (a *adapter) Adapt(root *aws2.RootAdapter, state *state.State) error {

	a.RootAdapter = root
	a.api = snsapi.NewFromConfig(root.SessionConfig())
	var err error

	state.AWS.SNS.Topics, err = a.getTopics()
	if err != nil {
		return err
	}

	return nil
}

func (a *adapter) getTopics() (queues []sns.Topic, err error) {

	a.Tracker().SetServiceLabel("Scanning queues...")

	batchQueues, token, err := a.getBatchTopics(nil)
	if err != nil {
		return nil, err
	}

	queues = append(queues, batchQueues...)

	for token != nil {
		batchQueues, token, err = a.getBatchTopics(token)
		if err != nil {
			return nil, err
		}
		queues = append(queues, batchQueues...)
	}

	return queues, nil
}

func (a *adapter) getBatchTopics(token *string) (topics []sns.Topic, nextToken *string, err error) {

	input := &snsapi.ListTopicsInput{}

	if token != nil {
		input.NextToken = token
	}

	apiTopics, err := a.api.ListTopics(a.Context(), input)
	if err != nil {
		return topics, nil, err
	}

	for _, topic := range apiTopics.Topics {

		topicMetadata := a.CreateMetadataFromARN(*topic.TopicArn)

		t := sns.NewTopic(*topic.TopicArn, topicMetadata)
		topicAttributes, err := a.api.GetTopicAttributes(a.Context(), &snsapi.GetTopicAttributesInput{
			TopicArn: topic.TopicArn,
		})
		if err != nil {
			return topics, nil, err
		}

		if kmsKeyID, ok := topicAttributes.Attributes["KmsMasterKeyId"]; ok {
			t.Encryption.KMSKeyID = types.String(kmsKeyID, topicMetadata)
		}

		topics = append(topics, t)
		a.Tracker().IncrementResource()
	}
	return topics, apiTopics.NextToken, nil

}
