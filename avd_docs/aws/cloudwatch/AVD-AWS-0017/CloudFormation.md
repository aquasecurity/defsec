
Enable CMK encryption of CloudWatch Log Groups

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Type: AWS::Logs::LogGroup
    Properties:
      KmsKeyId: "arn:aws:kms:us-west-2:111122223333:key/lambdalogging"
      LogGroupName: "aws/lambda/goodExample"
      RetentionInDays: 30
```
