
Turn on SQS Queue encryption

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
AWSTemplateFormatVersion: 2010-09-09
Description: Good example of queue
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      KmsMasterKeyId: some-key
      QueueName: my-queue
```
