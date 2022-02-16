package sns

import (
	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/trivy-config-parsers/cloudformation/parser"
)

func getTopics(ctx parser.FileContext) (topics []sns.Topic) {
	for _, r := range ctx.GetResourceByType("AWS::SNS::Topic") {

		topic := sns.Topic{
			Metadata: r.Metadata(),
			Encryption: sns.Encryption{
				KMSKeyID: r.GetStringProperty("KmsMasterKeyId"),
			},
		}

		topics = append(topics, topic)
	}
	return topics
}
