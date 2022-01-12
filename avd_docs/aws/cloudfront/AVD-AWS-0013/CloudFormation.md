
Use the most modern TLS/SSL policies available

```yaml
---
AWSTemplateFormatVersion: "2010-09-09"
Description: A sample template
Resources:
  GoodExample:
    Properties:
      DistributionConfig:
        DefaultCacheBehavior:
          TargetOriginId: target
          ViewerProtocolPolicy: https-only
        Enabled: true
        Logging:
          Bucket: logging-bucket
        Origins:
          - DomainName: https://some.domain
            Id: somedomain1
        ViewerCertificate:
          MinimumProtocolVersion: TLSv1.2_2021
    Type: AWS::CloudFront::Distribution
```
