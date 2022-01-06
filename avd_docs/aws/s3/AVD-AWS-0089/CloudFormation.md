---
additional_links: []
---

Add a logging block to the resource to enable access logging

```yaml
---
Resources:
  GoodExample:
    Properties:
      LoggingConfiguration:
        DestinationBucketName: logging-bucket
        LogFilePrefix: accesslogs/
    Type: AWS::S3::Bucket
```
