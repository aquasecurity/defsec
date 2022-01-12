
Add a logging block to the resource to enable access logging

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket
```
