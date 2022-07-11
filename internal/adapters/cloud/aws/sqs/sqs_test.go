package sqs

import (
	"fmt"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/go-mock-aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	sqsapi "github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"testing"

	aws2 "github.com/aquasecurity/defsec/internal/adapters/cloud/aws"
)

type queueDetails struct {
	queueName         string
	managedEncryption bool
}

func (q queueDetails) QueueURL(stack *localstack.Stack) string {
	return fmt.Sprintf("%s/000000000000/%s", stack.EndpointURL(), q.queueName)
}

func Test_SQSQueueEncrypted(t *testing.T) {

	tests := []struct {
		name    string
		details queueDetails
	}{
		{
			name: "simple queue with no managed encryption",
			details: queueDetails{
				queueName:         "test-queue",
				managedEncryption: false,
			},
		},
		{
			name: "simple queue with managed encryption",
			details: queueDetails{
				queueName:         "test-encrypted-queue",
				managedEncryption: true,
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapSQSQueue(t, ra, tt.details)

			testState := &state.State{}
			sqsAdapter := &adapter{}
			err = sqsAdapter.Adapt(ra, testState)
			require.NoError(t, err)

			assert.Len(t, testState.AWS.SQS.Queues, 1)
			var got sqs.Queue
			for _, q := range testState.AWS.SQS.Queues {
				if q.QueueURL.EqualTo(tt.details.QueueURL(stack)) {
					got = q
					break
				}
			}

			assert.Equal(t, tt.details.QueueURL(stack), got.QueueURL.Value())
			assert.Equal(t, tt.details.managedEncryption, got.Encryption.ManagedEncryption.Value())
			removeQueue(t, ra, tt.details.QueueURL(stack))
		})
	}
}

func bootstrapSQSQueue(t *testing.T, ra *aws2.RootAdapter, spec queueDetails) {

	api := sqsapi.NewFromConfig(ra.SessionConfig())

	queueAttributes := make(map[string]string)
	if spec.managedEncryption {
		queueAttributes[string(sqsTypes.QueueAttributeNameSqsManagedSseEnabled)] = "SSE-SQS"
	}

	queue, err := api.CreateQueue(ra.Context(), &sqsapi.CreateQueueInput{
		QueueName: aws.String(spec.queueName),
	})
	require.NoError(t, err)

	_, err = api.SetQueueAttributes(ra.Context(), &sqsapi.SetQueueAttributesInput{
		QueueUrl:   queue.QueueUrl,
		Attributes: queueAttributes,
	})
	require.NoError(t, err)
}

func removeQueue(t *testing.T, ra *aws2.RootAdapter, queueURL string) {

	api := sqsapi.NewFromConfig(ra.SessionConfig())

	_, err := api.DeleteQueue(ra.Context(), &sqsapi.DeleteQueueInput{
		QueueUrl: aws.String(queueURL),
	})
	require.NoError(t, err)
}
