package sns

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/aws/iam"
	iamp "github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/defsec/pkg/types"
	"github.com/liamg/iamgo"
)

func Adapt(modules terraform.Modules) sns.SNS {
	return sns.SNS{
		Topics:        adaptTopics(modules),
		Subscriptions: adaptSubscriptions(modules),
	}
}

func adaptTopics(modules terraform.Modules) []sns.Topic {
	var topics []sns.Topic
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sns_topic") {
			topics = append(topics, adaptTopic(resource, modules))
		}
	}
	return topics
}

func adaptSubscriptions(modules terraform.Modules) []sns.Subscription {
	var subscriptions []sns.Subscription
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType(" aws_sns_topic_subscription") {
			subscriptions = append(subscriptions, sns.Subscription{
				Metadata: resource.GetMetadata(),
				Endpoint: resource.GetAttribute("endpoint").AsStringValueOrDefault("", resource),
			})
		}
	}
	return subscriptions
}

func adaptTopic(resourceBlock *terraform.Block, modules terraform.Modules) sns.Topic {

	var policy iamp.Policy
	for _, policyBlock := range modules.GetResourcesByType("aws_sns_topic_policy") {

		policy = iamp.Policy{
			Metadata: policyBlock.GetMetadata(),
			Name:     types.StringDefault("", policyBlock.GetMetadata()),
			Document: iamp.Document{
				Metadata: policyBlock.GetMetadata(),
			},
			Builtin: types.Bool(false, policyBlock.GetMetadata()),
		}
		if attr := policyBlock.GetAttribute("policy"); attr.IsString() {
			dataBlock, err := modules.GetBlockById(attr.Value().AsString())
			if err != nil {
				parsed, err := iamgo.ParseString(attr.Value().AsString())
				if err != nil {
					continue
				}
				policy.Document.Parsed = *parsed
				policy.Document.Metadata = attr.GetMetadata()
			} else if dataBlock.Type() == "data" && dataBlock.TypeLabel() == "aws_iam_policy_document" {
				if doc, err := iam.ConvertTerraformDocument(modules, dataBlock); err == nil {
					policy.Document.Parsed = doc.Document
					policy.Document.Metadata = doc.Source.GetMetadata()
					policy.Document.IsOffset = true
				}
			}
		} else if refBlock, err := modules.GetReferencedBlock(attr, policyBlock); err == nil {
			if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
				if doc, err := iam.ConvertTerraformDocument(modules, refBlock); err == nil {
					policy.Document.Parsed = doc.Document
					policy.Document.Metadata = doc.Source.GetMetadata()
				}
			}
		}
	}
	return sns.Topic{
		Metadata:   resourceBlock.GetMetadata(),
		ARN:        types.StringDefault("", resourceBlock.GetMetadata()),
		Encryption: adaptEncryption(resourceBlock),
		Policy:     []iamp.Policy{policy},
	}
}

func adaptEncryption(resourceBlock *terraform.Block) sns.Encryption {
	return sns.Encryption{
		Metadata: resourceBlock.GetMetadata(),
		KMSKeyID: resourceBlock.GetAttribute("kms_master_key_id").AsStringValueOrDefault("", resourceBlock),
	}
}
