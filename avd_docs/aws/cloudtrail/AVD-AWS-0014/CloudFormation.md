
Enable Cloudtrail in all regions

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  BadExample:
    Type: AWS::CloudTrail::Trail
    Properties:
      IsLogging: true
      IsMultiRegionTrail: true     
      S3BucketName: "CloudtrailBucket"
      S3KeyPrefix: "/trailing"
      TrailName: "Cloudtrail"
```
