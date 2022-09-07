
Use a CMK for SNS Topic encryption

```yaml---
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of topic
Resources:
  Queue:
    Type: AWS::SQS::Topic
    Properties:
      TopicName: blah
      KmsMasterKeyId: some-key


```


